package user

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"
)

// ErrorResponse represents a standard error response
type ErrorResponse struct {
	Error   string            `json:"error"`
	Details map[string]string `json:"details,omitempty"`
}

// UserResponse and convertUserToResponse removed
// These were used by RegisterUserRoutes which required SQLite database access.
// User data now comes from Cognito via JWT claims.

// writeJSON writes a JSON response
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// writeError writes a JSON error response
func writeError(w http.ResponseWriter, status int, message string, details map[string]string) {
	writeJSON(w, status, ErrorResponse{
		Error:   message,
		Details: details,
	})
}

// RegisterUserRoutes removed
// This function and all user management routes required SQLite database access
// which is no longer supported. User management is now handled via Cognito.
// Use RequireAuthMiddleware() for authentication and SetupAuthRoutes() for OAuth flows.

// SetupAuthRoutes sets up all authentication routes using the global OAuth configuration
// This is the main entry point that replaces the complex manual setup
// Note: You must call SetOAuthConfig() first to configure OAuth settings
func SetupAuthRoutes(r chi.Router) error {
	// Use global configuration (required)
	config := getRequiredOIDCConfig()

	// Validate configuration
	if err := validateOAuthConfig(config); err != nil {
		return fmt.Errorf("invalid OAuth configuration: %w", err)
	}

	// Create state repository for OAuth state management
	// Always use encrypted state (stateless) - works in Lambda/serverless environments
	stateRepo := NewEncryptedStateRepository()
	log.Printf("✅ Using encrypted state repository (stateless)")

	// Create OAuth2 service using the consolidated config (JWT validation only, no database)
	oauth2Service, err := createOAuth2ServiceFromOAuthConfig(stateRepo, config)
	if err != nil {
		return fmt.Errorf("failed to create OAuth2 service: %w", err)
	}

	// Create OAuth2 handlers with internal helper functions
	oauth2Handlers := createOAuth2HandlersFromOAuthConfig(oauth2Service, config)

	// Setup authentication routes
	r.Get("/oauth2/idpresponse", oauth2Handlers.CallbackHandler)
	r.Get("/api/auth/login", oauth2Handlers.LoginHandler)
	r.Get("/api/auth/logout", oauth2Handlers.LogoutHandler)

	// Setup protected auth routes (requires authentication)
	r.Route("/api/auth", func(r chi.Router) {
		// Authentication middleware - JWT validation only
		r.Use(RequireAuthMiddleware())
		r.Get("/profile", createJWTProfileHandler())
	})

	log.Printf("✅ Authentication routes setup completed")
	return nil
}

// createOAuth2ServiceFromOAuthConfig creates OAuth2Service from OAuthConfig
// Note: Only validates JWT tokens, no database operations
func createOAuth2ServiceFromOAuthConfig(stateRepo StateRepository, config *OAuthConfig) (*OAuth2Service, error) {
	// Create OAuth2 service directly from OAuthConfig - JWT validation only
	return NewOAuth2ServiceFromOAuthConfig(stateRepo, config)
}

// createOAuth2HandlersFromOAuthConfig creates OAuth2Handlers with internal helper functions
func createOAuth2HandlersFromOAuthConfig(oauth2Service *OAuth2Service, config *OAuthConfig) *OAuth2Handlers {
	// Extract cookie domain from FrontEndURL
	frontEndURL, _ := url.Parse(config.FrontEndURL)
	cookieDomain := frontEndURL.Hostname()

	// Create handlers with internal helper functions
	return &OAuth2Handlers{
		oauth2Service:   oauth2Service,
		oauthConfig:     config,
		getFrontEndURL:  func() string { return config.FrontEndURL },
		getCookieDomain: func() string { return cookieDomain },
		createJWTCookie: CreateJWTCookie, // Use existing function
	}
}

// createJWTProfileHandler creates the profile endpoint handler using JWT claims only
func createJWTProfileHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get claims from context (set by auth middleware)
		claims, ok := GetClaimsFromContext(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "Not authenticated", nil)
			return
		}

		// Return user profile from JWT claims
		response := map[string]interface{}{
			"username":    claims.Username,
			"email":       claims.Email,
			"name":        fmt.Sprintf("%s %s", claims.GivenName, claims.FamilyName),
			"given_name":  claims.GivenName,
			"family_name": claims.FamilyName,
			"picture":     claims.Picture,
			"api_key":     claims.APIKey,
			"role":        claims.Role,
		}

		writeJSON(w, http.StatusOK, response)
	}
}
