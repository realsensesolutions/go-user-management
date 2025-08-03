package user

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
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
	if userID == "" || email == "" {
		return "", fmt.Errorf("user ID and email are required")
	}

	// Generate a secure random API key (implementation can be customized)
	apiKey := generateSecureAPIKey()

	err := s.repo.UpsertAPIKey(userID, email, apiKey)
	if err != nil {
		return "", fmt.Errorf("failed to store API key: %v", err)
	}

	return apiKey, nil
}

// UpdateAPIKey updates the API key for a user
func (s *userService) UpdateAPIKey(ctx context.Context, userID, email, apiKey string) error {
	if userID == "" || email == "" || apiKey == "" {
		return fmt.Errorf("user ID, email, and API key are required")
	}

	err := s.repo.UpsertAPIKey(userID, email, apiKey)
	if err != nil {
		return fmt.Errorf("failed to update API key: %v", err)
	}

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

// generateSecureAPIKey generates a cryptographically secure random API key
func generateSecureAPIKey() string {
	// Generate 32 random bytes (256 bits) for security
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to a simpler but still random approach if crypto/rand fails
		panic(fmt.Sprintf("failed to generate secure random bytes: %v", err))
	}
	
	// Convert to hex string and add prefix for identification
	return fmt.Sprintf("usr_%s", hex.EncodeToString(bytes))
}
