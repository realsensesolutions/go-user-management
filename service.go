package user

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var (
	// ErrUserNotFound is returned when a user is not found
	ErrUserNotFound = errors.New("user not found")
	// ErrInvalidAPIKey is returned when an API key is invalid
	ErrInvalidAPIKey = errors.New("invalid API key")
	// ErrUserAlreadyExists is returned when trying to create a user that already exists
	ErrUserAlreadyExists = errors.New("user already exists")
)

// Service provides user management operations
type Service interface {
	// GetUserByID retrieves a user by their ID
	GetUserByID(ctx context.Context, userID string) (*User, error)

	// GetUserByEmail retrieves a user by their email address
	GetUserByEmail(ctx context.Context, email string) (*User, error)

	// CreateUser creates a new user
	CreateUser(ctx context.Context, req CreateUserRequest) (*User, error)

	// UpdateUser updates an existing user
	UpdateUser(ctx context.Context, req UpdateUserRequest) (*User, error)

	// DeleteUser deletes a user by ID
	DeleteUser(ctx context.Context, userID string) error

	// ValidateAPIKey validates an API key and returns the associated user
	ValidateAPIKey(ctx context.Context, apiKey string) (*User, error)

	// GenerateAPIKey generates and stores a new API key for a user
	GenerateAPIKey(ctx context.Context, userID, email string) (string, error)

	// UpdateAPIKey updates the API key for a user
	UpdateAPIKey(ctx context.Context, userID, email, apiKey string) error

	// GetAPIKey retrieves the API key for a user
	GetAPIKey(ctx context.Context, userID string) (string, error)

	// ListUsers returns a list of users with pagination
	ListUsers(ctx context.Context, limit, offset int) ([]*User, error)
}

// userService implements the Service interface
type userService struct {
	repo Repository
}

// NewService creates a new user service with the provided repository
func NewService(repo Repository) Service {
	return &userService{
		repo: repo,
	}
}

// GetUserByID retrieves a user by their ID
func (s *userService) GetUserByID(ctx context.Context, userID string) (*User, error) {
	if userID == "" {
		return nil, fmt.Errorf("user ID cannot be empty")
	}

	user, err := s.repo.GetUserByID(userID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUserNotFound, err)
	}

	return user, nil
}

// GetUserByEmail retrieves a user by their email address
func (s *userService) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	if email == "" {
		return nil, fmt.Errorf("email cannot be empty")
	}

	user, err := s.repo.GetUserByEmail(email)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUserNotFound, err)
	}

	return user, nil
}

// CreateUser creates a new user
func (s *userService) CreateUser(ctx context.Context, req CreateUserRequest) (*User, error) {
	if req.ID == "" || req.Email == "" {
		return nil, fmt.Errorf("user ID and email are required")
	}

	// Check if user already exists
	existingUser, _ := s.repo.GetUserByID(req.ID)
	if existingUser != nil {
		return nil, ErrUserAlreadyExists
	}

	user, err := s.repo.CreateUser(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %v", err)
	}

	return user, nil
}

// UpdateUser updates an existing user
func (s *userService) UpdateUser(ctx context.Context, req UpdateUserRequest) (*User, error) {
	if req.ID == "" {
		return nil, fmt.Errorf("user ID is required")
	}

	user, err := s.repo.UpdateUser(req)
	if err != nil {
		return nil, fmt.Errorf("failed to update user: %v", err)
	}

	return user, nil
}

// DeleteUser deletes a user by ID
func (s *userService) DeleteUser(ctx context.Context, userID string) error {
	if userID == "" {
		return fmt.Errorf("user ID cannot be empty")
	}

	err := s.repo.DeleteUser(userID)
	if err != nil {
		return fmt.Errorf("failed to delete user: %v", err)
	}

	return nil
}

// ValidateAPIKey validates an API key and returns the associated user
func (s *userService) ValidateAPIKey(ctx context.Context, apiKey string) (*User, error) {
	if apiKey == "" {
		return nil, ErrInvalidAPIKey
	}

	user, err := s.repo.GetUserByAPIKey(apiKey)
	if err != nil {
		return nil, ErrInvalidAPIKey
	}

	return user, nil
}

// GenerateAPIKey generates and stores a new API key for a user
func (s *userService) GenerateAPIKey(ctx context.Context, userID, email string) (string, error) {
	fmt.Printf("🔍 [GENERATE_API_KEY] Called with userID='%s', email='%s'\n", userID, email)

	if userID == "" || email == "" {
		fmt.Printf("❌ [GENERATE_API_KEY] Missing required parameters: userID='%s', email='%s'\n", userID, email)
		return "", fmt.Errorf("user ID and email are required")
	}

	// Generate a secure random API key (implementation can be customized)
	apiKey := generateSecureAPIKey()
	fmt.Printf("🔍 [GENERATE_API_KEY] Generated API key: '%s'\n", apiKey)

	err := s.repo.UpsertAPIKey(userID, email, apiKey)
	if err != nil {
		fmt.Printf("❌ [GENERATE_API_KEY] Failed to store API key: %v\n", err)
		return "", fmt.Errorf("failed to store API key: %v", err)
	}

	fmt.Printf("✅ [GENERATE_API_KEY] Successfully generated and stored API key\n")
	return apiKey, nil
}

// UpdateAPIKey updates the API key for a user
func (s *userService) UpdateAPIKey(ctx context.Context, userID, email, apiKey string) error {
	fmt.Printf("🔄 [UPDATE_API_KEY] Updating API key for user '%s' to '%s'\n", userID, apiKey)

	if userID == "" || email == "" || apiKey == "" {
		return fmt.Errorf("user ID, email, and API key are required")
	}

	err := s.repo.UpsertAPIKey(userID, email, apiKey)
	if err != nil {
		fmt.Printf("❌ [UPDATE_API_KEY] Failed to update in DB: %v\n", err)
		return fmt.Errorf("failed to update API key: %v", err)
	}

	fmt.Printf("✅ [UPDATE_API_KEY] Successfully updated API key in DB\n")
	return nil
}

// GetAPIKey retrieves the API key for a user
func (s *userService) GetAPIKey(ctx context.Context, userID string) (string, error) {
	if userID == "" {
		return "", fmt.Errorf("user ID cannot be empty")
	}

	apiKey, err := s.repo.GetAPIKey(userID)
	if err != nil {
		return "", fmt.Errorf("failed to get API key: %v", err)
	}

	return apiKey, nil
}

// ListUsers returns a list of users with pagination
func (s *userService) ListUsers(ctx context.Context, limit, offset int) ([]*User, error) {
	if limit <= 0 {
		limit = 20 // Default limit
	}
	if offset < 0 {
		offset = 0
	}

	users, err := s.repo.ListUsers(ctx, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %v", err)
	}

	return users, nil
}

// generateSecureAPIKey generates a secure random API key
// This is a basic implementation - in production, you might want to use a more sophisticated approach
func generateSecureAPIKey() string {
	// This is a placeholder implementation
	// In a real implementation, you would generate a cryptographically secure random string
	return fmt.Sprintf("usr_%d", time.Now().UnixNano())
}
