package user

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// User represents a user in the system (Cognito-backed, but Cognito-agnostic)
type User struct {
	Email      string `json:"email"` // Primary identifier
	GivenName  string `json:"givenName"`
	FamilyName string `json:"familyName"`
	Picture    string `json:"picture"`
	Role       string `json:"role"`
	APIKey     string `json:"apiKey,omitempty"` // Omitted if not set
}

// CreateUserRequest represents a request to create a new user
type CreateUserRequest struct {
	Email      string `json:"email"`
	GivenName  string `json:"givenName"`
	FamilyName string `json:"familyName"`
	Picture    string `json:"picture,omitempty"`
	Role       string `json:"role,omitempty"`
}

// ProfileUpdate represents fields that can be updated in a user profile
type ProfileUpdate struct {
	GivenName  *string `json:"givenName,omitempty"`
	FamilyName *string `json:"familyName,omitempty"`
	Picture    *string `json:"picture,omitempty"`
}

// OAuthConfig holds complete OAuth2/Cognito authentication configuration
// This replaces and consolidates CognitoConfig and OAuth2Config into a single, cleaner interface
type OAuthConfig struct {
	// Required Cognito/OAuth2 fields
	ClientID     string   `json:"clientId"`
	ClientSecret string   `json:"clientSecret"`
	UserPoolID   string   `json:"userPoolId"`
	RedirectURI  string   `json:"redirectUri"` // Full URL, path extracted internally
	Region       string   `json:"region"`
	Domain       string   `json:"domain,omitempty"` // For logout URL construction
	FrontEndURL  string   `json:"frontEndUrl"`      // Frontend base URL
	Scopes       []string `json:"scopes"`

	// Business logic injection
	CalculateDefaultRole func(*OIDCClaims) string `json:"-"` // Custom role calculation

	// STS credential exchange configuration
	STSRoleARN         string `json:"stsRoleArn,omitempty"`         // IAM role ARN for STS AssumeRoleWithWebIdentity
	STSSessionName     string `json:"stsSessionName,omitempty"`     // Optional session name prefix (defaults to "user-session")
	STSDurationSeconds int32  `json:"stsDurationSeconds,omitempty"` // Optional duration in seconds (defaults to 3600)
}

// STSCredentials represents temporary AWS credentials obtained via STS
type STSCredentials struct {
	AccessKeyID     string    `json:"accessKeyId"`
	SecretAccessKey string    `json:"secretAccessKey"`
	SessionToken    string    `json:"sessionToken"`
	Expiration      time.Time `json:"expiration"`
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
	Sub               string     `json:"sub"`
	Aud               string     `json:"aud"`
	Iss               string     `json:"iss"`
	TokenUse          string     `json:"token_use"`
	Scope             string     `json:"scope"`
	Groups            []string   `json:"cognito:groups"`
	Username          string     `json:"cognito:username"`
	Email             string     `json:"email"`
	EmailVerified     bool       `json:"email_verified"`
	Name              string     `json:"name"`
	GivenName         string     `json:"given_name"`
	FamilyName        string     `json:"family_name"`
	Picture           string     `json:"picture"`         // Added for Google profile picture
	Identities        []Identity `json:"identities"`      // Added for identity provider information
	APIKey            string     `json:"custom:apiKey"`   // Backend-baked API key
	UserRole          string     `json:"custom:userRole"` // User role from Cognito custom attribute
	TenantID          string     `json:"custom:tenantId"`
	ServiceProviderID string     `json:"custom:serviceProviderId"`
	Exp               int64      `json:"exp"`
	Iat               int64      `json:"iat"`
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
