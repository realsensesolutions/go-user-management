package user

import (
	"context"
	"fmt"
	"log"
	"time"

	"golang.org/x/oauth2"
)

// OAuth2Service handles complete OAuth2/OIDC flows
// Note: Only validates JWT tokens, no database operations
type OAuth2Service struct {
	stateRepo           StateRepository
	oauthConfig         *OAuthConfig
	oauth2ConfigFactory func() (*oauth2.Config, error)
}

// NewOAuth2ServiceFromOAuthConfig creates a new OAuth2 service with OAuthConfig
// Note: Only validates JWT tokens, no database operations
func NewOAuth2ServiceFromOAuthConfig(stateRepo StateRepository, oauthConfig *OAuthConfig) (*OAuth2Service, error) {
	// Validate required configuration for OAuth2
	if err := validateOAuthConfig(oauthConfig); err != nil {
		return nil, fmt.Errorf("OAuth2 service creation failed: %v", err)
	}

	return &OAuth2Service{
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

// GenerateAuthURL generates an OAuth2 authorization URL with state management.
// If loginHint is non-empty, it is forwarded to the provider via the login_hint parameter.
func (s *OAuth2Service) GenerateAuthURL(redirectURL, loginHint string) (string, error) {
	log.Printf("🔍 [OAuth2Service] Starting GenerateAuthURL for redirectURL: %s", redirectURL)

	oauth2Config, err := s.buildOAuth2Config()
	if err != nil {
		log.Printf("❌ [OAuth2Service] Failed to initialize OAuth2 config: %v", err)
		return "", fmt.Errorf("failed to initialize OAuth2 config: %w", err)
	}
	log.Printf("✅ [OAuth2Service] OAuth2 config initialized successfully")

	nonce, err := GenerateSecureState()
	if err != nil {
		log.Printf("❌ [OAuth2Service] Failed to generate nonce: %v", err)
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	log.Printf("✅ [OAuth2Service] Generated secure nonce: %s", nonce[:8]+"...")

	log.Printf("🔄 [OAuth2Service] About to prepare state...")
	startTime := time.Now()
	err = s.stateRepo.StoreState(nonce, redirectURL, time.Now().Add(5*time.Minute))
	duration := time.Since(startTime)

	if err != nil {
		log.Printf("❌ [OAuth2Service] Failed to prepare state after %v: %v", duration, err)
		return "", fmt.Errorf("failed to prepare state: %w", err)
	}
	log.Printf("✅ [OAuth2Service] State prepared successfully in %v", duration)

	var oauthState string
	if encryptedRepo, ok := s.stateRepo.(*EncryptedStateRepository); ok {
		oauthState, err = encryptedRepo.GenerateEncryptedState(nonce, redirectURL)
		if err != nil {
			return "", fmt.Errorf("failed to generate encrypted state: %w", err)
		}
		log.Printf("✅ [OAuth2Service] Generated encrypted state token (length: %d)", len(oauthState))
	} else {
		oauthState = nonce
		log.Printf("✅ [OAuth2Service] Using nonce as state (stored in database)")
	}

	opts := []oauth2.AuthCodeOption{oauth2.AccessTypeOffline}
	if loginHint != "" {
		opts = append(opts, oauth2.SetAuthURLParam("login_hint", loginHint))
	}

	authURL := oauth2Config.AuthCodeURL(oauthState, opts...)
	log.Printf("✅ [OAuth2Service] Generated auth URL successfully")
	return authURL, nil
}

// buildOAuth2Config returns the oauth2.Config to use, preferring the injected factory when set.
func (s *OAuth2Service) buildOAuth2Config() (*oauth2.Config, error) {
	if s.oauth2ConfigFactory != nil {
		return s.oauth2ConfigFactory()
	}
	return s.createOAuth2Config()
}

// HandleCallback processes an OAuth2 callback and returns user claims, raw ID token, and redirect URL
func (s *OAuth2Service) HandleCallback(code, state string) (*Claims, string, string, error) {
	log.Printf("🔍 [HandleCallback] === Starting OAuth Callback Processing ===")
	log.Printf("🔍 [HandleCallback] Code length: %d", len(code))
	log.Printf("🔍 [HandleCallback] State length: %d", len(state))
	log.Printf("🔍 [HandleCallback] State preview: %s", func() string {
		if len(state) > 20 {
			return state[:20] + "..."
		}
		return state
	}())

	if code == "" {
		log.Printf("❌ [HandleCallback] Missing authorization code")
		return nil, "", "", fmt.Errorf("missing authorization code")
	}

	if state == "" {
		log.Printf("❌ [HandleCallback] Missing state parameter")
		return nil, "", "", fmt.Errorf("missing state parameter")
	}

	// Validate state parameter and get redirect URL
	log.Printf("🔄 [HandleCallback] Validating state parameter...")
	redirectURL, isValid := s.stateRepo.ValidateAndRemoveState(state)
	if !isValid {
		log.Printf("❌ [HandleCallback] State validation failed - invalid or expired")
		statePreview := state
		if len(state) > 20 {
			statePreview = state[:20] + "..."
		}
		log.Printf("🔍 [HandleCallback] State that failed: %s", statePreview)
		return nil, "", "", fmt.Errorf("invalid or expired state parameter")
	}
	log.Printf("✅ [HandleCallback] State validated successfully, redirect URL: %s", redirectURL)

	// Initialize OAuth2 config
	oauth2Config, err := s.createOAuth2Config()
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to initialize OAuth2 config: %w", err)
	}

	// Exchange authorization code for tokens
	log.Printf("🔄 [HandleCallback] Exchanging authorization code for tokens...")
	log.Printf("🔍 [HandleCallback] OAuth2 Config - ClientID: %s, RedirectURI: %s", oauth2Config.ClientID, oauth2Config.RedirectURL)
	token, err := oauth2Config.Exchange(context.Background(), code)
	if err != nil {
		log.Printf("❌ [HandleCallback] Token exchange failed: %v", err)
		log.Printf("🔍 [HandleCallback] Error type: %T", err)
		return nil, "", "", fmt.Errorf("failed to exchange code for token: %w", err)
	}
	log.Printf("✅ [HandleCallback] Token exchange successful")
	log.Printf("🔍 [HandleCallback] Token type: %s", token.TokenType)
	log.Printf("🔍 [HandleCallback] Token expiry: %v", token.Expiry)

	// Extract ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		log.Printf("❌ [HandleCallback] No ID token in response")
		return nil, "", "", fmt.Errorf("no ID token in response")
	}
	log.Printf("✅ [HandleCallback] ID token extracted, length: %d", len(rawIDToken))

	// Validate ID token
	log.Printf("🔄 [HandleCallback] Validating ID token...")
	claims, err := ValidateOIDCTokenFromOAuthConfig(context.Background(), rawIDToken, s.oauthConfig)
	if err != nil {
		log.Printf("❌ [HandleCallback] ID token validation failed: %v", err)
		log.Printf("🔍 [HandleCallback] Error type: %T", err)
		return nil, "", "", fmt.Errorf("failed to validate ID token: %w", err)
	}
	log.Printf("✅ [HandleCallback] ID token validated successfully")
	log.Printf("🔍 [HandleCallback] Claims - Email: %s, Username: %s, Sub: %s, GivenName: %s, FamilyName: %s",
		claims.Email, claims.Username, claims.Sub, claims.GivenName, claims.FamilyName)

	// JWT validation only - no database operations
	log.Printf("✅ [HandleCallback] === OAuth Callback Processing Completed Successfully ===")
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
