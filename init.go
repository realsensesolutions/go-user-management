package user

// init is intentionally empty - no database migrations needed
// This package is now JWT/Cognito-only with encrypted stateless OAuth state
func init() {
	// No database initialization needed
	// All user data comes from Cognito
	// OAuth state uses encrypted tokens (stateless)
}

