# Link Shortener

Este proyecto es un acortador de enlaces que permite a los usuarios gestionar sus URLs de manera sencilla y segura, utilizando autenticación OAuth de GitHub y protección adicional mediante HMAC y cookies.

## Endpoints

- **GET `/login`**  
  Redirige al usuario al flujo de autenticación de GitHub OAuth.

- **GET `/callback`**  
  Endpoint de callback para la autenticación de GitHub. Aquí se procesa el token recibido después del login.

- **GET `/api/urls`**  
  Lista todas las URLs acortadas asociadas al usuario autenticado.

- **POST `/api/urls`**  
  Crea una nueva URL acortada para el usuario.

- **PUT `/api/urls/:id`**  
  Actualiza una URL acortada existente.

- **DELETE `/api/urls/:id`**  
  Elimina una URL acortada.

- **GET `/:short`**  
  Redirecciona a la URL original asociada al código acortado.

---

## Autenticación y Seguridad

Este proyecto utiliza el login de GitHub mediante OAuth para autenticar a los usuarios. Para asegurar la integridad y autenticidad de la sesión, utiliza HMAC (Hash-based Message Authentication Code) junto con cookies.

- **OAuth de GitHub**: Permite la autenticación segura sin almacenar contraseñas.
- **HMAC con cookies**: Se utiliza para firmar y verificar la validez de las cookies de sesión, evitando manipulaciones y accesos no autorizados.

### Diferencia con cookies de terceros

En este proyecto, las cookies se configuran como **First-Party Cookies** (cookies propias), es decir, son gestionadas directamente por el backend del acortador. Esto contrasta con las **Third-Party Cookies** (cookies de terceros), que son generadas por dominios distintos al del sitio web principal y suelen estar sujetas a mayores restricciones de seguridad en los navegadores modernos. Al usar cookies propias y HMAC, se mejora la seguridad y compatibilidad del sistema de autenticación.

---

## Diagrama de la Base de Datos

![Diagrama de la base de datos](https://github.com/user-attachments/assets/54d8c083-8a63-4c9e-8154-657112d3b1a6)
