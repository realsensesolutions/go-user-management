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
	userService Service
	stateRepo   StateRepository
	oauthConfig *OAuthConfig
}

// NewOAuth2ServiceFromOAuthConfig creates a new OAuth2 service with OAuthConfig
func NewOAuth2ServiceFromOAuthConfig(userService Service, stateRepo StateRepository, oauthConfig *OAuthConfig) (*OAuth2Service, error) {
	// Validate required configuration for OAuth2
	if err := validateOAuthConfig(oauthConfig); err != nil {
		return nil, fmt.Errorf("OAuth2 service creation failed: %v", err)
	}

	return &OAuth2Service{
		userService: userService,
		stateRepo:   stateRepo,
		oauthConfig: oauthConfig,
	}, nil
}

// validateOAuthConfig validates that all required OAuthConfig fields are provided
func validateOAuthConfig(config *OAuthConfig) error {
	if config == nil {
		return fmt.Errorf("OAuthConfig cannot be nil")
	}

	var missing []string

	if config.ClientID == "" {
		missing = append(missing, "ClientID")
	}
	if config.ClientSecret == "" {
		missing = append(missing, "ClientSecret")
	}
	if config.UserPoolID == "" {
		missing = append(missing, "UserPoolID")
	}
	if config.RedirectURI == "" {
		missing = append(missing, "RedirectURI")
	}
	if config.Region == "" {
		missing = append(missing, "Region")
	}
	if config.FrontEndURL == "" {
		missing = append(missing, "FrontEndURL")
	}
	if len(config.Scopes) == 0 {
		missing = append(missing, "Scopes")
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing required OAuthConfig fields: %v", missing)
	}

	return nil
}

// GenerateAuthURL generates an OAuth2 authorization URL with state management
func (s *OAuth2Service) GenerateAuthURL(redirectURL string) (string, error) {
	log.Printf("🔍 [OAuth2Service] Starting GenerateAuthURL for redirectURL: %s", redirectURL)

	// Initialize OAuth2 config
	oauth2Config, err := s.createOAuth2Config()
	if err != nil {
		log.Printf("❌ [OAuth2Service] Failed to initialize OAuth2 config: %v", err)
		return "", fmt.Errorf("failed to initialize OAuth2 config: %w", err)
	}
	log.Printf("✅ [OAuth2Service] OAuth2 config initialized successfully")

	// Generate secure state parameter
	state, err := GenerateSecureState()
	if err != nil {
		log.Printf("❌ [OAuth2Service] Failed to generate state: %v", err)
		return "", fmt.Errorf("failed to generate state: %w", err)
	}
	log.Printf("✅ [OAuth2Service] Generated secure state: %s", state[:8]+"...")

	// Store state with expiration (5 minutes) and redirect URL
	log.Printf("🔄 [OAuth2Service] About to store state in repository...")
	startTime := time.Now()
	err = s.stateRepo.StoreState(state, redirectURL, time.Now().Add(5*time.Minute))
	duration := time.Since(startTime)

	if err != nil {
		log.Printf("❌ [OAuth2Service] Failed to store state after %v: %v", duration, err)
		return "", fmt.Errorf("failed to store state: %w", err)
	}
	log.Printf("✅ [OAuth2Service] State stored successfully in %v", duration)

	// Generate authorization URL
	authURL := oauth2Config.AuthCodeURL(state, oauth2.AccessTypeOffline)
	log.Printf("✅ [OAuth2Service] Generated auth URL successfully")
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
	claims, err := ValidateOIDCTokenFromOAuthConfig(context.Background(), rawIDToken, s.oauthConfig)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to validate ID token: %w", err)
	}

	// Create or update user in database with role calculation
	err = s.upsertUser(claims)
	if err != nil {
		log.Printf("❌ Failed to create/update user: %v", err)
		// Don't fail the authentication, just log the error
	}

	return claims, rawIDToken, redirectURL, nil
}

// createOAuth2Config creates an OAuth2 configuration
func (s *OAuth2Service) createOAuth2Config() (*oauth2.Config, error) {
	if s.oauthConfig.ClientID == "" {
		return nil, fmt.Errorf("ClientID is required in OAuthConfig")
	}

	// Initialize provider if not already done
	provider, err := initOIDCProviderFromOAuthConfig(s.oauthConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize OIDC provider: %w", err)
	}

	config := &oauth2.Config{
		ClientID:     s.oauthConfig.ClientID,
		ClientSecret: s.oauthConfig.ClientSecret,
		RedirectURL:  s.oauthConfig.RedirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       s.oauthConfig.Scopes,
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
		// Calculate default role using the provided function
		defaultRole := "user" // fallback default
		if s.oauthConfig.CalculateDefaultRole != nil {
			// Convert Claims to OIDCClaims for role calculation
			oidcClaims := s.convertClaimsToOIDCClaims(claims)
			defaultRole = s.oauthConfig.CalculateDefaultRole(oidcClaims)
		}

		createReq := CreateUserRequest{
			ID:         claims.Email,
			Email:      claims.Email,
			GivenName:  claims.GivenName,
			FamilyName: claims.FamilyName,
			Picture:    claims.Picture,
			Role:       defaultRole,
		}

		_, err = s.userService.CreateUser(context.Background(), createReq)
		if err != nil && err != ErrUserAlreadyExists {
			return fmt.Errorf("failed to create user: %w", err)
		}
	}

	return nil
}

// convertClaimsToOIDCClaims converts standardized Claims back to OIDCClaims for role calculation
func (s *OAuth2Service) convertClaimsToOIDCClaims(claims *Claims) *OIDCClaims {
	return &OIDCClaims{
		Sub:        claims.Sub,
		Email:      claims.Email,
		GivenName:  claims.GivenName,
		FamilyName: claims.FamilyName,
		Picture:    claims.Picture,
		Username:   claims.Username,
		APIKey:     claims.APIKey,
		// Additional fields would be populated from the original token if needed
	}
}
