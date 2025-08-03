package user

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// User represents a generic user in the system
type User struct {
	ID         string    `json:"id" db:"id"`
	Email      string    `json:"email" db:"email"`
	GivenName  string    `json:"givenName" db:"given_name"`
	FamilyName string    `json:"familyName" db:"family_name"`
	Picture    string    `json:"picture" db:"picture"`
	Role       string    `json:"role" db:"role"`
	APIKey     string    `json:"apiKey" db:"api_key"`
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

// CognitoConfig holds complete Cognito configuration
type CognitoConfig struct {
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	UserPoolID   string `json:"userPoolId"`
	RedirectURI  string `json:"redirectUri"`
	Region       string `json:"region"`
	Domain       string `json:"domain,omitempty"` // For logout URL construction
}

// OAuth2Config holds OAuth2 configuration
type OAuth2Config struct {
	ClientID     string   `json:"clientId"`
	ClientSecret string   `json:"clientSecret"`
	RedirectPath string   `json:"redirectPath"`
	Scopes       []string `json:"scopes"`
	ProviderURL  string   `json:"providerUrl"`
	RedirectURI  string   `json:"redirectUri"`
}

// FlexibleBool is a custom type that can unmarshal from both boolean and string values
type FlexibleBool bool

// UnmarshalJSON implements the json.Unmarshaler interface for FlexibleBool
func (fb *FlexibleBool) UnmarshalJSON(data []byte) error {
	var b bool
	if err := json.Unmarshal(data, &b); err == nil {
		*fb = FlexibleBool(b)
		return nil
	}

	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		parsed, err := strconv.ParseBool(s)
		if err != nil {
			return fmt.Errorf("cannot parse %q as boolean", s)
		}
		*fb = FlexibleBool(parsed)
		return nil
	}

	return fmt.Errorf("cannot unmarshal %s into FlexibleBool", string(data))
}

// Bool returns the boolean value of FlexibleBool
func (fb FlexibleBool) Bool() bool {
	return bool(fb)
}

// OIDCClaims represents the claims in an OIDC token
type OIDCClaims struct {
	Sub           string     `json:"sub"`
	Aud           string     `json:"aud"`
	Iss           string     `json:"iss"`
	TokenUse      string     `json:"token_use"`
	Scope         string     `json:"scope"`
	Groups        []string   `json:"cognito:groups"`
	Username      string     `json:"cognito:username"`
	Email         string     `json:"email"`
	EmailVerified bool       `json:"email_verified"`
	Name          string     `json:"name"`
	GivenName     string     `json:"given_name"`
	FamilyName    string     `json:"family_name"`
	Picture       string     `json:"picture"`       // Added for Google profile picture
	Identities    []Identity `json:"identities"`    // Added for identity provider information
	APIKey        string     `json:"custom:apiKey"` // Backend-baked API key
	Exp           int64      `json:"exp"`
	Iat           int64      `json:"iat"`
}

// Identity represents identity provider information from Cognito
type Identity struct {
	UserId       string       `json:"userId"`
	ProviderName string       `json:"providerName"` // e.g., "Google", "Cognito"
	ProviderType string       `json:"providerType"` // e.g., "Google", "Cognito"
	IsSocial     FlexibleBool `json:"issocial"`     // true for social providers like Google
	Primary      FlexibleBool `json:"primary"`      // indicates primary identity
	DateCreated  string       `json:"dateCreated"`  // when this identity was created
}
