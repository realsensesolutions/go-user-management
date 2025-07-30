package user

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// mockRepository implements Repository interface for testing
type mockRepository struct {
	users  map[string]*User
	apiKeys map[string]string // apiKey -> userID
}

func newMockRepository() *mockRepository {
	return &mockRepository{
		users:   make(map[string]*User),
		apiKeys: make(map[string]string),
	}
}

func (m *mockRepository) GetUserByID(userID string) (*User, error) {
	user, exists := m.users[userID]
	if !exists {
		return nil, ErrUserNotFound
	}
	return user, nil
}

func (m *mockRepository) GetUserByEmail(email string) (*User, error) {
	for _, user := range m.users {
		if user.Email == email {
			return user, nil
		}
	}
	return nil, ErrUserNotFound
}

func (m *mockRepository) CreateUser(req CreateUserRequest) (*User, error) {
	if _, exists := m.users[req.ID]; exists {
		return nil, ErrUserAlreadyExists
	}
	
	user := &User{
		ID:         req.ID,
		Email:      req.Email,
		GivenName:  req.GivenName,
		FamilyName: req.FamilyName,
		Picture:    req.Picture,
		Role:       req.Role,
	}
	
	m.users[req.ID] = user
	return user, nil
}

func (m *mockRepository) UpdateUser(req UpdateUserRequest) (*User, error) {
	user, exists := m.users[req.ID]
	if !exists {
		return nil, ErrUserNotFound
	}
	
	if req.Email != nil {
		user.Email = *req.Email
	}
	if req.GivenName != nil {
		user.GivenName = *req.GivenName
	}
	if req.FamilyName != nil {
		user.FamilyName = *req.FamilyName
	}
	if req.Picture != nil {
		user.Picture = *req.Picture
	}
	if req.Role != nil {
		user.Role = *req.Role
	}
	
	return user, nil
}

func (m *mockRepository) DeleteUser(userID string) error {
	if _, exists := m.users[userID]; !exists {
		return ErrUserNotFound
	}
	delete(m.users, userID)
	return nil
}

func (m *mockRepository) GetAPIKey(userID string) (string, error) {
	for apiKey, uid := range m.apiKeys {
		if uid == userID {
			return apiKey, nil
		}
	}
	return "", nil
}

func (m *mockRepository) UpsertAPIKey(userID, email, apiKey string) error {
	m.apiKeys[apiKey] = userID
	return nil
}

func (m *mockRepository) GetUserByAPIKey(apiKey string) (*User, error) {
	userID, exists := m.apiKeys[apiKey]
	if !exists {
		return nil, ErrInvalidAPIKey
	}
	return m.GetUserByID(userID)
}

func (m *mockRepository) ListUsers(ctx context.Context, limit, offset int) ([]*User, error) {
	var users []*User
	count := 0
	skipped := 0
	
	for _, user := range m.users {
		if skipped < offset {
			skipped++
			continue
		}
		if count >= limit {
			break
		}
		users = append(users, user)
		count++
	}
	
	return users, nil
}

func TestUserService_GetUserByID(t *testing.T) {
	repo := newMockRepository()
	service := NewService(repo)
	ctx := context.Background()
	
	// Create test user
	testUser := &User{
		ID:    "test-user",
		Email: "test@example.com",
	}
	repo.users["test-user"] = testUser
	
	// Test successful retrieval
	user, err := service.GetUserByID(ctx, "test-user")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if user.ID != "test-user" {
		t.Errorf("Expected user ID 'test-user', got %s", user.ID)
	}
	
	// Test user not found
	_, err = service.GetUserByID(ctx, "nonexistent")
	if !errors.Is(err, ErrUserNotFound) {
		t.Errorf("Expected ErrUserNotFound, got %v", err)
	}
	
	// Test empty ID
	_, err = service.GetUserByID(ctx, "")
	if err == nil {
		t.Error("Expected error for empty user ID")
	}
}

func TestUserService_CreateUser(t *testing.T) {
	repo := newMockRepository()
	service := NewService(repo)
	ctx := context.Background()
	
	req := CreateUserRequest{
		ID:         "new-user",
		Email:      "new@example.com",
		GivenName:  "New",
		FamilyName: "User",
		Role:       "user",
	}
	
	// Test successful creation
	user, err := service.CreateUser(ctx, req)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if user.ID != req.ID {
		t.Errorf("Expected user ID %s, got %s", req.ID, user.ID)
	}
	
	// Test duplicate creation
	_, err = service.CreateUser(ctx, req)
	if !errors.Is(err, ErrUserAlreadyExists) {
		t.Errorf("Expected ErrUserAlreadyExists, got %v", err)
	}
	
	// Test invalid request
	invalidReq := CreateUserRequest{
		ID:    "", // Empty ID
		Email: "test@example.com",
	}
	_, err = service.CreateUser(ctx, invalidReq)
	if err == nil {
		t.Error("Expected error for invalid request")
	}
}

func TestUserService_ValidateAPIKey(t *testing.T) {
	repo := newMockRepository()
	service := NewService(repo)
	ctx := context.Background()
	
	// Setup test data
	testUser := &User{
		ID:    "test-user",
		Email: "test@example.com",
	}
	repo.users["test-user"] = testUser
	repo.apiKeys["valid-key"] = "test-user"
	
	// Test valid API key
	user, err := service.ValidateAPIKey(ctx, "valid-key")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if user.ID != "test-user" {
		t.Errorf("Expected user ID 'test-user', got %s", user.ID)
	}
	
	// Test invalid API key
	_, err = service.ValidateAPIKey(ctx, "invalid-key")
	if !errors.Is(err, ErrInvalidAPIKey) {
		t.Errorf("Expected ErrInvalidAPIKey, got %v", err)
	}
	
	// Test empty API key
	_, err = service.ValidateAPIKey(ctx, "")
	if !errors.Is(err, ErrInvalidAPIKey) {
		t.Errorf("Expected ErrInvalidAPIKey, got %v", err)
	}
}

func TestUserService_ListUsers(t *testing.T) {
	repo := newMockRepository()
	service := NewService(repo)
	ctx := context.Background()
	
	// Add test users
	for i := 0; i < 5; i++ {
		userID := fmt.Sprintf("user-%d", i)
		repo.users[userID] = &User{
			ID:    userID,
			Email: fmt.Sprintf("user%d@example.com", i),
		}
	}
	
	// Test listing users
	users, err := service.ListUsers(ctx, 3, 0)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if len(users) != 3 {
		t.Errorf("Expected 3 users, got %d", len(users))
	}
	
	// Test with offset
	users, err = service.ListUsers(ctx, 2, 2)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if len(users) != 2 {
		t.Errorf("Expected 2 users, got %d", len(users))
	}
}