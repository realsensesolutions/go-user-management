-- Rollback: Add role constraints back (restore original CHECK constraint)
-- SQLite doesn't support ADD CONSTRAINT directly, so we need to recreate the table

-- Create new table with role constraints
CREATE TABLE users_new (
    id TEXT PRIMARY KEY,                -- This IS the email address
    given_name TEXT NOT NULL,
    family_name TEXT NOT NULL,
    picture TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL CHECK (role IN ('admin', 'user')) DEFAULT 'user',  -- Restore CHECK constraint
    api_key TEXT NOT NULL DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Copy existing data (will fail if there are custom roles)
INSERT INTO users_new (id, given_name, family_name, picture, role, api_key, created_at, updated_at)
SELECT id, given_name, family_name, picture, role, api_key, created_at, updated_at
FROM users;

-- Drop the old table
DROP TABLE users;

-- Rename the new table to the original name
ALTER TABLE users_new RENAME TO users;

-- Recreate the indexes
CREATE INDEX IF NOT EXISTS idx_users_api_key ON users(api_key) WHERE api_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);