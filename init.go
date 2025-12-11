package user

// init is intentionally empty - no database migrations needed
// This package is now JWT/Cognito-only with encrypted stateless OAuth state
func init() {
	// No database initialization needed
	// All user data comes from Cognito
	// OAuth state uses encrypted tokens (stateless)
}

// ValidateUserSchema removed
// This function required SQLite database access which is no longer supported.
// User schema validation is now handled by Cognito.
func ValidateUserSchema() error {
	// No-op: user schema is managed by Cognito
	return nil
}
