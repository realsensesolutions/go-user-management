package user

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

var (
	oidcProvider  *oidc.Provider
	oidcVerifier  *oidc.IDTokenVerifier
	providerMutex sync.Mutex
)

// initOIDCProvider initializes the OIDC provider
func initOIDCProvider() (*oidc.Provider, error) {
	providerMutex.Lock()
	defer providerMutex.Unlock()

	if oidcProvider != nil {
		return oidcProvider, nil
	}

	userPoolID := os.Getenv("COGNITO_USER_POOL_ID")
	region := os.Getenv("AWS_REGION")

	if userPoolID == "" {
		return nil, fmt.Errorf("COGNITO_USER_POOL_ID environment variable is required")
	}

	issuerURL := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s", region, userPoolID)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var err error
	oidcProvider, err = oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	// Initialize the ID token verifier
	clientID := os.Getenv("COGNITO_CLIENT_ID")
	if clientID == "" {
		return nil, fmt.Errorf("COGNITO_CLIENT_ID environment variable is required")
	}

	oidcVerifier = oidcProvider.Verifier(&oidc.Config{
		ClientID: clientID,
	})

	log.Printf("✅ OIDC provider initialized for issuer: %s", issuerURL)
	return oidcProvider, nil
}

// ValidateOIDCToken validates an OIDC ID token and returns claims
func ValidateOIDCToken(ctx context.Context, tokenString string) (*Claims, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("empty token")
	}

	// Initialize verifier if not already done
	if oidcVerifier == nil {
		_, err := initOIDCProvider()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize OIDC provider: %w", err)
		}
	}

	// Verify the ID token
	idToken, err := oidcVerifier.Verify(ctx, tokenString)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	// Extract claims into temporary OIDC structure for JWT parsing
	var oidcClaims OIDCClaims
	if err := idToken.Claims(&oidcClaims); err != nil {
		return nil, fmt.Errorf("failed to extract claims: %w", err)
	}

	// Convert to standardized Claims format
	claims := &Claims{
		Sub:        oidcClaims.Sub,
		Email:      oidcClaims.Email,
		GivenName:  oidcClaims.GivenName,
		FamilyName: oidcClaims.FamilyName,
		Picture:    oidcClaims.Picture,
		Username:   oidcClaims.Username,
		APIKey:     oidcClaims.APIKey,
		Role:       "user", // Default role, could be derived from cognito:groups if needed
		Provider:   "oidc",
	}

	return claims, nil
}

// Helper methods for OIDCClaims

// IsGoogleUser returns true if the user authenticated via Google
func (c *OIDCClaims) IsGoogleUser() bool {
	for _, identity := range c.Identities {
		if identity.ProviderName == "Google" || identity.ProviderType == "Google" {
			return true
		}
	}
	return false
}

// IsSocialUser returns true if the user authenticated via any social provider
func (c *OIDCClaims) IsSocialUser() bool {
	for _, identity := range c.Identities {
		if identity.IsSocial.Bool() {
			return true
		}
	}
	return false
}

// GetPrimaryIdentity returns the primary identity provider information
func (c *OIDCClaims) GetPrimaryIdentity() *Identity {
	for _, identity := range c.Identities {
		if identity.Primary.Bool() {
			return &identity
		}
	}
	// If no primary identity found, return the first one
	if len(c.Identities) > 0 {
		return &c.Identities[0]
	}
	return nil
}

// GetProviderName returns the name of the identity provider used for authentication
func (c *OIDCClaims) GetProviderName() string {
	primaryIdentity := c.GetPrimaryIdentity()
	if primaryIdentity != nil {
		return primaryIdentity.ProviderName
	}
	return "Unknown"
}

// HasProfilePicture returns true if the user has a profile picture from their provider
func (c *OIDCClaims) HasProfilePicture() bool {
	return c.Picture != ""
}