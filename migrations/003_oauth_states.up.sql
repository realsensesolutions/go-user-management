-- OAuth2 state management table
CREATE TABLE IF NOT EXISTS oauth_states (
    id TEXT PRIMARY KEY,
    state TEXT UNIQUE NOT NULL,
    redirect_url TEXT,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

-- Indexes for efficient lookups
CREATE INDEX IF NOT EXISTS idx_oauth_states_state ON oauth_states(state);
CREATE INDEX IF NOT EXISTS idx_oauth_states_expires_at ON oauth_states(expires_at);