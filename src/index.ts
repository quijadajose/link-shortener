export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const { pathname, searchParams } = url;
    const ALLOWED_ORIGINS = ["https://link-shortener.quijadajosed.workers.dev"];
    // Verificación de Origin para mutaciones
    const method = request.method.toUpperCase();
    if (["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
      const origin = request.headers.get("Origin");
      if (!origin || !ALLOWED_ORIGINS.includes(origin)) {
        return new Response("Forbidden", { status: 403 });
      }
    }
    // Cabeceras de seguridad antes de devolver
    const headers = new Headers();
    headers.set(
      "Strict-Transport-Security",
      "max-age=63072000; includeSubDomains; preload"
    );
    headers.set("X-Frame-Options", "DENY");
    headers.set("X-Content-Type-Options", "nosniff");
    headers.set("Content-Security-Policy", "default-src 'self';");

    // Redirección al login de github
    if (pathname === "/login") {
      const redirect = `https://github.com/login/oauth/authorize?client_id=${env.GITHUB_CLIENT_ID}&redirect_uri=${env.OAUTH_CALLBACK_URL}&scope=read:user`;
      return Response.redirect(redirect, 302);
    }
    if (pathname === "/logout" && method === "POST") {
      const cookie = request.headers.get("Cookie") || "";
      const sessionMatch = cookie.match(/session=([^;]+)/);
      const sessionToken = sessionMatch?.[1];

      if (sessionToken) {
        await env.DB.prepare("DELETE FROM sessions WHERE token = ?")
          .bind(sessionToken)
          .run();
      }

      return new Response(null, {
        status: 302,
        headers: {
          // Para borrar la cookie se establece una fecha de expiración en el pasado
          "Set-Cookie": `session=; HttpOnly; Secure; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Lax`,
          Location: "/",
        },
      });
    }

    // --- GitHub OAuth Callback ---
    if (pathname === "/callback") {
      try {
        const code = searchParams.get("code");
        if (!code) {
          return new Response("Missing code", { status: 400 });
        }

        // Intercambiar código por access token
        const tokenResp = await fetch(
          "https://github.com/login/oauth/access_token",
          {
            method: "POST",
            headers: {
              Accept: "application/json",
              "Content-Type": "application/json",
            },
            body: JSON.stringify({
              client_id: env.GITHUB_CLIENT_ID,
              client_secret: env.GITHUB_CLIENT_SECRET,
              code,
            }),
          }
        );

        const contentType = tokenResp.headers.get("content-type") || "";
        const rawTokenResponse = await tokenResp.text();

        if (!tokenResp.ok) {
          console.error("GitHub token exchange failed", {
            status: tokenResp.status,
            response: rawTokenResponse,
          });
          return new Response("Failed to exchange code for access token", {
            status: 500,
          });
        }

        if (!contentType.includes("application/json")) {
          console.error("Unexpected token response", rawTokenResponse);
          return new Response("Unexpected response format from GitHub", {
            status: 500,
          });
        }

        const tokenJson = JSON.parse(rawTokenResponse);
        const accessToken = tokenJson.access_token;
        console.log("Access token:", accessToken);

        if (!accessToken) {
          console.error("Missing access_token in GitHub response", tokenJson);
          return new Response("Access token not received", { status: 500 });
        }
        // Obtener información del usuario
        const userResp = await fetch("https://api.github.com/user", {
          headers: {
            Authorization: `Bearer ${accessToken}`,
            "User-Agent": "link-shortener-worker",
            Accept: "application/vnd.github+json",
          },
        });

        if (!userResp.ok) {
          const userErr = await userResp.text();
          console.error("GitHub user fetch failed:", userErr);
          console.error("Failed to fetch GitHub user", {
            status: userResp.status,
            body: userErr,
          });
          return new Response("Failed to fetch GitHub user", { status: 500 });
        }

        const user = await userResp.json();
        const userId = user.id?.toString();
        const username = user.login;
        const avatarUrl = user.avatar_url;

        if (!userId || !username) {
          console.error("Incomplete user data", user);
          return new Response("Invalid GitHub user data", { status: 500 });
        }

        // Guardar o actualizar en la base de datos
        await env.DB.prepare(
          `
          INSERT INTO users (id, username, avatar_url)
          VALUES (?, ?, ?)
          ON CONFLICT(id) DO UPDATE SET
            username = excluded.username,
            avatar_url = excluded.avatar_url
        `
        )
          .bind(userId, username, avatarUrl)
          .run();

        // Crear sesión
        const sessionToken = await createSessionToken(
          userId,
          env.SESSION_SECRET,
          env
        );

        // Redirigir al dashboard con cookie de sesión
        return new Response(null, {
          status: 302,
          headers: {
            "Set-Cookie": `session=${sessionToken}; HttpOnly; Secure; Path=/; SameSite=Lax`,
            Location: "/dashboard",
          },
        });
      } catch (err) {
        console.error("Unexpected error in /callback handler", err);
        return new Response("Internal Server Error", { status: 500 });
      }
    }

    const cookie = request.headers.get("Cookie") || "";
    const sessionMatch = cookie.match(/session=([^;]+)/);
    const sessionToken = sessionMatch?.[1];

    let userId = null;
    if (sessionToken) {
      userId = await verifySessionToken(sessionToken, env.SESSION_SECRET, env);
    }

    if (pathname === "/api/urls" && method === "POST") {
      if (!userId) return new Response("Unauthorized", { status: 401 });
      const { original_url, custom_id } = await request.json();

      const id = custom_id || generateRandomId();

      const exists = await env.DB.prepare("SELECT 1 FROM urls WHERE id = ?")
        .bind(id)
        .first();
      if (exists && custom_id)
        return Response.json(
          { message: "Custom ID already taken" },
          { status: 409 }
        );

      await env.DB.prepare(
        `
        INSERT INTO urls (id, original_url, user_id, created_at)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
      `
      )
        .bind(id, original_url, userId)
        .run();

      return Response.json({ short_url: `${url.origin}/${id}` });
    }

    if (pathname === "/api/urls" && method === "GET") {
      if (!userId) return new Response("Unauthorized", { status: 401 });
      const result = await env.DB.prepare(
        "SELECT * FROM urls WHERE user_id = ?"
      )
        .bind(userId)
        .all();
      return Response.json(result.results);
    }

    if (pathname.startsWith("/api/urls/") && method === "PUT") {
      if (!userId) return new Response("Unauthorized", { status: 401 });
      const id = pathname.split("/").pop();
      const { new_url } = await request.json();

      await env.DB.prepare(
        `
        UPDATE urls SET original_url = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND user_id = ?
      `
      )
        .bind(new_url, id, userId)
        .run();

      return new Response("Updated", { status: 200 });
    }

    if (pathname.startsWith("/api/urls/") && method === "DELETE") {
      if (!userId) return new Response("Unauthorized", { status: 401 });
      const id = pathname.split("/").pop();
      await env.DB.prepare("DELETE FROM urls WHERE id = ? AND user_id = ?")
        .bind(id, userId)
        .run();
      return new Response("Deleted", { status: 200 });
    }

    // Redirect short URL
    const match = await env.DB.prepare(
      "SELECT original_url FROM urls WHERE id = ?"
    )
      .bind(pathname.slice(1))
      .first();
    if (match) {
      const redirectUrl = ensureAbsoluteUrl(match.original_url);
      return Response.redirect(redirectUrl, 302);
    }
    if (url.pathname === "/" || url.pathname === "/dashboard") {
      const isLoggedIn = userId !== null;

      let dashboardContent = "";
      if (isLoggedIn) {
        let currentUser = null;
        if (userId) {
          // Fetch user details for dashboard display
          currentUser = await env.DB.prepare(
            "SELECT username, avatar_url FROM users WHERE id = ?"
          )
            .bind(userId)
            .first();
        }
        dashboardContent = `
          <h1>${
            currentUser?.avatar_url
              ? `<img src="${currentUser.avatar_url}" alt="Avatar" style="width: 50px; height: 50px; border-radius: 50%; margin-right: 10px; vertical-align: middle;">`
              : ""
          }Bienvenido, ${currentUser?.username || "Usuario"}!</h1>
          <p>Aquí puedes administrar tus enlaces.</p>
          <button id="addLinkBtn">Agregar nuevo enlace</button>
          <button id="viewLinksBtn">Regrescar lista de enlaces</button>
          <button id="logoutBtn">Cerrar sesión</button>
          <div id="linksContainer"></div>
          <script>
            document.addEventListener('DOMContentLoaded', () => {
              const addLinkBtn = document.getElementById('addLinkBtn');
              const viewLinksBtn = document.getElementById('viewLinksBtn');
              const logoutBtn = document.getElementById('logoutBtn');
              const linksContainer = document.getElementById('linksContainer');

              addLinkBtn.addEventListener('click', async () => {
              const original_url = prompt("Ingresa la URL original:");
              if (!original_url) return;
              const custom_id = prompt("Ingresa un ID personalizado (opcional):");

              const response = await fetch('/api/urls', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ original_url, custom_id })
              });
              const data = await response.json();
              if (response.ok) {
                alert('URL corta creada: ' + data.short_url);
                viewLinksBtn.click(); // Refresh links
              } else if (response.status === 409) {
                alert('El ID personalizado ya está en uso. Por favor elige otro.');
              } else {
                alert('Error: ' + (data.message || response.statusText));
              }
            });

              viewLinksBtn.addEventListener('click', async () => {
                const response = await fetch('/api/urls');
                if (!response.ok) {
                  alert('Error al cargar los enlaces.');
                  return;
                }
                const links = await response.json();
                linksContainer.innerHTML = ''; // Clear previous links
                if (links.length === 0) {
                  linksContainer.innerHTML = '<p>No hay enlaces creados aún.</p>';
                  return;
                }
                const ul = document.createElement('ul');
                links.forEach(link => {
                  const li = document.createElement('li');
                  li.innerHTML = \`
                  <a href="/\${link.id}" target="_blank">/\${link.id}</a> ->
                  <a href="\${link.original_url.startsWith('http') ? link.original_url : 'https://' + link.original_url}" target="_blank">\${link.original_url}</a>
                  <button data-id="\${link.id}" class="edit-btn">Editar</button>
                  <button data-id="\${link.id}" class="delete-btn">Eliminar</button>
                \`;
                  ul.appendChild(li);
                });
                linksContainer.appendChild(ul);

                // Add event listeners for edit/delete buttons
                linksContainer.querySelectorAll('.edit-btn').forEach(btn => {
                  btn.addEventListener('click', async (e) => {
                    const id = e.target.dataset.id;
                    const new_url = prompt("Ingresa la nueva URL para " + id + ":");
                    if (!new_url) return;
                    const response = await fetch(\`/api/urls/\${id}\`, {
                      method: 'PUT',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({ new_url })
                    });
                    if (response.ok) {
                      alert('Enlace actualizado!');
                      viewLinksBtn.click(); // Refresh links
                    } else {
                      alert('Error al actualizar el enlace.');
                    }
                  });
                });

                linksContainer.querySelectorAll('.delete-btn').forEach(btn => {
                  btn.addEventListener('click', async (e) => {
                    const id = e.target.dataset.id;
                    if (!confirm("¿Estás seguro de que quieres eliminar " + id + "?")) return;
                    const response = await fetch(\`/api/urls/\${id}\`, {
                      method: 'DELETE'
                    });
                    if (response.ok) {
                      alert('Enlace eliminado!');
                      viewLinksBtn.click(); // Refresh links
                    } else {
                      alert('Error al eliminar el enlace.');
                    }
                  });
                });
              });

              logoutBtn.addEventListener('click', async () => {
                await fetch('/logout', { method: 'POST' });
                window.location.href = '/';
              });

              // Automatically load links if on dashboard and logged in
              if (viewLinksBtn && (window.location.pathname === '/dashboard'|| window.location.pathname === '/')) {
                viewLinksBtn.click();
                console.log('click')
              }
            });
          </script>
        `;
      } else {
        dashboardContent = `
          <h1>Link Shortener</h1>
          <p>Inicia sesión para administrar enlaces.</p>
          <button onclick="window.location.href='/login'" style="display: flex; align-items: center; justify-content: center; gap: 8px; padding: 10px 16px; background-color: #24292f; color: white; border: none; border-radius: 4px; cursor: pointer;">
          <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" viewBox="0 0 16 16" style="margin-right: 8px;">
          <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8"/>
        </svg>
          Iniciar sesión con GitHub
        </button>

        `;
      }

      return new Response(
        `<!DOCTYPE html>
        <html lang="es">
          <head>
            <meta charset="UTF-8" />
            <meta name="viewport" content="width=device-width, initial-scale=1.0" />
            <title>Link Shortener</title>
            <style>
              :root {
                --bg-color: #f4f4f4;
                --container-bg: white;
                --text-color: #333;
                --link-color: #0070f3;
                --button-bg: #007bff;
                --button-hover-bg: #0056b3;
                --button-text: white;
                --list-item-bg: #f9f9f9;
                --border-color: #eee;
                --shadow-color: rgba(0,0,0,0.1);
                --secondary-button-bg: #6c757d;
                --secondary-button-hover-bg: #5a6268;
              }

              @media (prefers-color-scheme: dark) {
                :root {
                  --bg-color: #121212;
                  --container-bg: #1e1e1e;
                  --text-color: #e0e0e0;
                  --link-color: #58a6ff;
                  --button-bg: #3b82f6;
                  --button-hover-bg: #2563eb;
                  --list-item-bg: #2c2c2c;
                  --border-color: #373737;
                  --shadow-color: rgba(0,0,0,0.4);
                  --secondary-button-bg: #495057;
                  --secondary-button-hover-bg: #343a40;
                }
              }

              body {
                font-family: sans-serif;
                margin: 0;
                padding: 2rem;
                background: var(--bg-color);
                color: var(--text-color);
                transition: background-color 0.2s, color 0.2s;
              }
              .container {
                max-width: 800px;
                margin: 0 auto;
                background: var(--container-bg);
                border-radius: 8px;
                padding: 2rem;
                box-shadow: 0 2px 8px var(--shadow-color);
                transition: background-color 0.2s;
              }
              h1 {
                color: var(--text-color);
              }
              .link {
                margin-top: 1rem;
                display: inline-block;
                color: var(--link-color);
              }
              button {
                margin-right: 10px;
                padding: 8px 15px;
                border: none;
                border-radius: 4px;
                background-color: var(--button-bg);
                color: var(--button-text);
                cursor: pointer;
                transition: background-color 0.2s;
              }
              button:hover {
                background-color: var(--button-hover-bg);
              }
              #linksContainer {
                margin-top: 20px;
                border-top: 1px solid var(--border-color);
                padding-top: 20px;
                transition: border-color 0.2s;
              }
              #linksContainer ul {
                list-style: none;
                padding: 0;
              }
              #linksContainer li {
                background: var(--list-item-bg);
                margin-bottom: 10px;
                padding: 10px;
                border-radius: 5px;
                display: flex;
                align-items: center;
                gap: 10px;
                transition: background-color 0.2s;
              }
              #linksContainer li a {
                color: var(--link-color);
              }
              #linksContainer li .edit-btn {
                margin-left: auto;
              }
              #linksContainer li .edit-btn,
              #linksContainer li .delete-btn {
                background-color: var(--secondary-button-bg);
              }
              #linksContainer li .edit-btn:hover,
              #linksContainer li .delete-btn:hover {
                background-color: var(--secondary-button-hover-bg);
              }
            </style>
          </head>
          <body>
            <div class="container">${dashboardContent}</div>
          </body>
        </html>`,
        {
          headers: {
            "Content-Type": "text/html; charset=utf-8",
          },
        }
      );
    }

    return new Response("Not found", { status: 404 });
  },
};

function generateRandomId(length = 6) {
  const chars =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  return Array.from(crypto.getRandomValues(new Uint8Array(length)))
    .map((x) => chars[x % chars.length])
    .join("");
}

async function createSessionToken(userId, secret, env) {
  const timestamp = Date.now().toString();
  const data = `${userId}.${timestamp}`;
  const hmac = await signHMAC(data, secret);
  const token = `${userId}.${timestamp}.${hmac}`;
  await env.DB.prepare("INSERT INTO sessions (token, user_id) VALUES (?, ?)")
    .bind(token, userId)
    .run();
  return token;
}

async function verifySessionToken(token, secret, env) {
  const [userId, timestamp, hmac] = token.split(".");
  if (!userId || !timestamp || !hmac) return null;

  const expectedHmac = await signHMAC(`${userId}.${timestamp}`, secret);
  if (expectedHmac !== hmac) return null;

  const age = Date.now() - Number(timestamp);
  if (age > 1000 * 60 * 60 * 24 * 7) return null;

  const session = await env.DB.prepare(
    "SELECT user_id FROM sessions WHERE token = ?"
  )
    .bind(token)
    .first();
  return session?.user_id || null;
}

async function signHMAC(data, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(data)
  );
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
function ensureAbsoluteUrl(url) {
  if (/^https?:\/\//i.test(url)) return url;
  return `https://${url}`;
}
