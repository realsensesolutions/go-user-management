-- Initial users table with all required columns
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    given_name TEXT,
    family_name TEXT,
    picture TEXT,
    role TEXT DEFAULT 'user',
    api_key TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Performance indexes
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_api_key ON users(api_key) WHERE api_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);