package user

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OAuth2Service handles complete OAuth2/OIDC flows
type OAuth2Service struct {
	userService Service
	stateRepo   StateRepository
	config      *OAuth2Config
}

// NewOAuth2Service creates a new OAuth2 service with environment validation
func NewOAuth2Service(userService Service, stateRepo StateRepository, config *OAuth2Config) *OAuth2Service {
	// Validate required environment variables for OAuth2
	if err := validateOAuth2Environment(); err != nil {
		panic(fmt.Sprintf("OAuth2 service creation failed: %v", err))
	}

	return &OAuth2Service{
		userService: userService,
		stateRepo:   stateRepo,
		config:      config,
	}
}

// GenerateAuthURL generates an OAuth2 authorization URL with state management
func (s *OAuth2Service) GenerateAuthURL(redirectURL string) (string, error) {
	// Initialize OAuth2 config
	oauth2Config, err := s.createOAuth2Config()
	if err != nil {
		return "", fmt.Errorf("failed to initialize OAuth2 config: %w", err)
	}

	// Generate secure state parameter
	state, err := GenerateSecureState()
	if err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
	}

	// Store state with expiration (5 minutes) and redirect URL
	err = s.stateRepo.StoreState(state, redirectURL, time.Now().Add(5*time.Minute))
	if err != nil {
		return "", fmt.Errorf("failed to store state: %w", err)
	}

	// Generate authorization URL
	authURL := oauth2Config.AuthCodeURL(state, oauth2.AccessTypeOffline)
	return authURL, nil
}

// HandleCallback processes an OAuth2 callback and returns user claims and raw ID token
func (s *OAuth2Service) HandleCallback(code, state string) (*Claims, string, error) {
	if code == "" {
		return nil, "", fmt.Errorf("missing authorization code")
	}

	if state == "" {
		return nil, "", fmt.Errorf("missing state parameter")
	}

	// Validate state parameter and get redirect URL
	_, isValid := s.stateRepo.ValidateAndRemoveState(state)
	if !isValid {
		return nil, "", fmt.Errorf("invalid or expired state parameter")
	}

	// Initialize OAuth2 config
	oauth2Config, err := s.createOAuth2Config()
	if err != nil {
		return nil, "", fmt.Errorf("failed to initialize OAuth2 config: %w", err)
	}

	// Exchange authorization code for tokens
	log.Printf("🔄 Exchanging authorization code for tokens...")
	token, err := oauth2Config.Exchange(context.Background(), code)
	if err != nil {
		return nil, "", fmt.Errorf("failed to exchange code for token: %w", err)
	}

	// Extract ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, "", fmt.Errorf("no ID token in response")
	}

	// Validate ID token
	claims, err := ValidateOIDCToken(context.Background(), rawIDToken)
	if err != nil {
		return nil, "", fmt.Errorf("failed to validate ID token: %w", err)
	}

	// Create or update user in database
	err = s.upsertUser(claims)
	if err != nil {
		log.Printf("❌ Failed to create/update user: %v", err)
		// Don't fail the authentication, just log the error
	}

	return claims, rawIDToken, nil
}

// createOAuth2Config creates an OAuth2 configuration
func (s *OAuth2Service) createOAuth2Config() (*oauth2.Config, error) {
	clientID := os.Getenv("COGNITO_CLIENT_ID")
	clientSecret := os.Getenv("COGNITO_CLIENT_SECRET")

	if clientID == "" {
		return nil, fmt.Errorf("COGNITO_CLIENT_ID environment variable is required")
	}

	// Initialize provider if not already done
	provider, err := initOIDCProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize OIDC provider: %w", err)
	}

	config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  os.Getenv("COGNITO_REDIRECT_URI"), // Use redirect URI from environment
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}

	return config, nil
}

// upsertUser creates or updates a user record in the database
func (s *OAuth2Service) upsertUser(claims *Claims) error {
	// Revert to original working pattern - check if user exists first
	existingUser, err := s.userService.GetUserByEmail(context.Background(), claims.Email)
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		return fmt.Errorf("failed to check user existence: %w", err)
	}

	// If user doesn't exist, create them
	if existingUser == nil {
		createReq := CreateUserRequest{
			ID:         claims.Email,
			Email:      claims.Email,
			GivenName:  claims.GivenName,
			FamilyName: claims.FamilyName,
			Picture:    claims.Picture,
			Role:       "user",
		}

		_, err = s.userService.CreateUser(context.Background(), createReq)
		if err != nil && err != ErrUserAlreadyExists {
			return fmt.Errorf("failed to create user: %w", err)
		}
	}

	return nil
}

// validateOAuth2Environment validates that all required OAuth2 environment variables are set
func validateOAuth2Environment() error {
	required := map[string]string{
		"COGNITO_CLIENT_ID":     os.Getenv("COGNITO_CLIENT_ID"),
		"COGNITO_CLIENT_SECRET": os.Getenv("COGNITO_CLIENT_SECRET"),
		"COGNITO_USER_POOL_ID":  os.Getenv("COGNITO_USER_POOL_ID"),
		"COGNITO_REDIRECT_URI":  os.Getenv("COGNITO_REDIRECT_URI"),
		"AWS_REGION":            os.Getenv("AWS_REGION"),
	}

	var missing []string
	for key, value := range required {
		if value == "" {
			missing = append(missing, key)
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing required OAuth2 environment variables: %v", missing)
	}

	return nil
}
