-- Initial users table with all required columns
-- Uses email address as primary key to maintain compatibility with existing foreign keys
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,                -- This IS the email address
    given_name TEXT NOT NULL,
    family_name TEXT NOT NULL,
    picture TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL CHECK (role IN ('admin', 'user')) DEFAULT 'user',
    api_key TEXT NOT NULL DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Performance indexes
-- Note: No separate email index needed since id IS the email
CREATE INDEX IF NOT EXISTS idx_users_api_key ON users(api_key) WHERE api_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);