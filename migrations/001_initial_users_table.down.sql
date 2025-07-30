-- Rollback initial users table
DROP INDEX IF EXISTS idx_users_role;
DROP INDEX IF EXISTS idx_users_api_key;
DROP INDEX IF EXISTS idx_users_email;
DROP TABLE IF EXISTS users;