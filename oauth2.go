package user

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"golang.org/x/oauth2"
)

// OAuth2Service handles complete OAuth2/OIDC flows
type OAuth2Service struct {
	userService   Service
	stateRepo     StateRepository
	config        *OAuth2Config
	cognitoConfig *CognitoConfig
}

// NewOAuth2Service creates a new OAuth2 service with configuration validation
func NewOAuth2Service(userService Service, stateRepo StateRepository, config *OAuth2Config, cognitoConfig *CognitoConfig) *OAuth2Service {
	// Validate required configuration for OAuth2
	if err := validateOAuth2Config(config, cognitoConfig); err != nil {
		panic(fmt.Sprintf("OAuth2 service creation failed: %v", err))
	}

	return &OAuth2Service{
		userService:   userService,
		stateRepo:     stateRepo,
		config:        config,
		cognitoConfig: cognitoConfig,
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

// HandleCallback processes an OAuth2 callback and returns user claims, raw ID token, and redirect URL
func (s *OAuth2Service) HandleCallback(code, state string) (*Claims, string, string, error) {
	if code == "" {
		return nil, "", "", fmt.Errorf("missing authorization code")
	}

	if state == "" {
		return nil, "", "", fmt.Errorf("missing state parameter")
	}

	// Validate state parameter and get redirect URL
	redirectURL, isValid := s.stateRepo.ValidateAndRemoveState(state)
	if !isValid {
		return nil, "", "", fmt.Errorf("invalid or expired state parameter")
	}

	// Initialize OAuth2 config
	oauth2Config, err := s.createOAuth2Config()
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to initialize OAuth2 config: %w", err)
	}

	// Exchange authorization code for tokens
	log.Printf("🔄 Exchanging authorization code for tokens...")
	token, err := oauth2Config.Exchange(context.Background(), code)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to exchange code for token: %w", err)
	}

	// Extract ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, "", "", fmt.Errorf("no ID token in response")
	}

	// Validate ID token
	claims, err := ValidateOIDCToken(context.Background(), rawIDToken, s.cognitoConfig)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to validate ID token: %w", err)
	}

	// Create or update user in database
	err = s.upsertUser(claims)
	if err != nil {
		log.Printf("❌ Failed to create/update user: %v", err)
		// Don't fail the authentication, just log the error
	}

	return claims, rawIDToken, redirectURL, nil
}

// createOAuth2Config creates an OAuth2 configuration
func (s *OAuth2Service) createOAuth2Config() (*oauth2.Config, error) {
	if s.cognitoConfig.ClientID == "" {
		return nil, fmt.Errorf("ClientID is required in CognitoConfig")
	}

	// Initialize provider if not already done
	provider, err := initOIDCProvider(s.cognitoConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize OIDC provider: %w", err)
	}

	config := &oauth2.Config{
		ClientID:     s.cognitoConfig.ClientID,
		ClientSecret: s.cognitoConfig.ClientSecret,
		RedirectURL:  s.config.RedirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       s.config.Scopes,
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

// validateOAuth2Config validates that all required OAuth2 configuration is provided
func validateOAuth2Config(config *OAuth2Config, cognitoConfig *CognitoConfig) error {
	if config == nil {
		return fmt.Errorf("OAuth2Config cannot be nil")
	}

	if cognitoConfig == nil {
		return fmt.Errorf("CognitoConfig cannot be nil")
	}

	var missing []string

	if cognitoConfig.ClientID == "" {
		missing = append(missing, "CognitoConfig.ClientID")
	}
	if cognitoConfig.ClientSecret == "" {
		missing = append(missing, "CognitoConfig.ClientSecret")
	}
	if cognitoConfig.UserPoolID == "" {
		missing = append(missing, "CognitoConfig.UserPoolID")
	}
	if cognitoConfig.RedirectURI == "" {
		missing = append(missing, "CognitoConfig.RedirectURI")
	}
	if cognitoConfig.Region == "" {
		missing = append(missing, "CognitoConfig.Region")
	}
	if config.RedirectURI == "" {
		missing = append(missing, "OAuth2Config.RedirectURI")
	}
	if len(config.Scopes) == 0 {
		missing = append(missing, "OAuth2Config.Scopes")
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing required OAuth2 configuration fields: %v", missing)
	}

	return nil
}
