package user

import "context"

// Repository defines the interface for user data access operations
type Repository interface {
	// GetUserByID retrieves a user by their ID
	GetUserByID(userID string) (*User, error)

	// GetUserByEmail retrieves a user by their email address
	GetUserByEmail(email string) (*User, error)

	// CreateUser creates a new user
	CreateUser(req CreateUserRequest) (*User, error)

	// UpdateUser updates an existing user
	UpdateUser(req UpdateUserRequest) (*User, error)

	// DeleteUser deletes a user by ID
	DeleteUser(userID string) error

	// GetAPIKey returns a stored API key for a user or empty string if none
	GetAPIKey(userID string) (string, error)

	// UpsertAPIKey saves the API key for the given user, inserting user row with minimal data if necessary
	UpsertAPIKey(userID, email, apiKey string) error

	// GetUserByAPIKey finds a user by their API key
	GetUserByAPIKey(apiKey string) (*User, error)

	// ListUsers returns a list of users (with optional filtering)
	ListUsers(ctx context.Context, limit, offset int) ([]*User, error)
}