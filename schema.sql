-- Users from GitHub OAuth
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, -- GitHub user ID
  username TEXT NOT NULL,
  avatar_url TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Shortened URLs
CREATE TABLE IF NOT EXISTS urls (
  id TEXT PRIMARY KEY, -- short code
  original_url TEXT NOT NULL,
  user_id TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
