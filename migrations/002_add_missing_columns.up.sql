-- Migration for existing databases that might be missing columns
-- This is safe to run multiple times due to IF NOT EXISTS and ALTER TABLE IF COLUMN NOT EXISTS patterns

-- Add missing columns if they don't exist (SQLite doesn't support IF NOT EXISTS for columns, so we use a workaround)
-- We'll handle this in the Go code using schema introspection

-- For now, this is a placeholder that the Go migration code will use to know
-- it needs to check and add missing columns dynamically

-- Add performance indexes that might be missing
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_api_key ON users(api_key) WHERE api_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);