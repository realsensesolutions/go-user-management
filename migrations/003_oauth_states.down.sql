-- Drop OAuth2 state management table
DROP INDEX IF EXISTS idx_oauth_states_expires_at;
DROP INDEX IF EXISTS idx_oauth_states_state;
DROP TABLE IF EXISTS oauth_states;