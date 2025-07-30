package user

import "time"

// User represents a generic user in the system
type User struct {
	ID         string    `json:"id" db:"id"`
	Email      string    `json:"email" db:"email"`
	GivenName  string    `json:"givenName" db:"given_name"`
	FamilyName string    `json:"familyName" db:"family_name"`
	Picture    string    `json:"picture" db:"picture"`
	Role       string    `json:"role" db:"role"`
	CreatedAt  time.Time `json:"createdAt" db:"created_at"`
	UpdatedAt  time.Time `json:"updatedAt" db:"updated_at"`
}

// CreateUserRequest represents a request to create a new user
type CreateUserRequest struct {
	ID         string `json:"id"`
	Email      string `json:"email"`
	GivenName  string `json:"givenName"`
	FamilyName string `json:"familyName"`
	Picture    string `json:"picture,omitempty"`
	Role       string `json:"role,omitempty"`
}

// UpdateUserRequest represents a request to update an existing user
type UpdateUserRequest struct {
	ID         string  `json:"id"`
	Email      *string `json:"email,omitempty"`
	GivenName  *string `json:"givenName,omitempty"`
	FamilyName *string `json:"familyName,omitempty"`
	Picture    *string `json:"picture,omitempty"`
	Role       *string `json:"role,omitempty"`
}