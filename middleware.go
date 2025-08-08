package user

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
)

var (
	// Package-level OAuth configuration
	globalOAuthConfig *OAuthConfig
)

// SetOAuthConfig sets the global OAuth configuration for OIDC validation
// This allows consumers to configure OAuth settings programmatically instead of using environment variables
func SetOAuthConfig(config *OAuthConfig) {
	globalOAuthConfig = config
}

// GetOAuthConfig returns the current global OAuth configuration (for testing/debugging)
func GetOAuthConfig() *OAuthConfig {
	return globalOAuthConfig
}

// Define a custom type for the context key to avoid collisions
type contextKey string

// ClaimsKey is the key for storing user claims in the request context
const ClaimsKey = contextKey("claims")

// UserKey is the key for storing user object in the request context
const UserKey = contextKey("user")

// Claims represents authentication claims for both JWT and API key authentication
type Claims struct {
	Sub        string `json:"sub"`         // User ID
	Email      string `json:"email"`       // User email
	GivenName  string `json:"given_name"`  // User first name
	FamilyName string `json:"family_name"` // User last name
	Picture    string `json:"picture"`     // Profile picture URL
	Username   string `json:"username"`    // Username (usually email)
	APIKey     string `json:"api_key"`     // API key if used for auth
	Role       string `json:"role"`        // User role
	Provider   string `json:"provider"`    // Auth provider (jwt, api_key)
}

// AuthConfig holds configuration for authentication middleware
type AuthConfig struct {
	Service      Service                                                 // User service for API key validation
	CookieName   string                                                  // JWT cookie name (default: "jwt")
	APIKeyHeader string                                                  // API key header name (default: "X-Api-Key")
	RequireAuth  bool                                                    // Whether auth is required (default: true)
	ErrorHandler func(w http.ResponseWriter, r *http.Request, err error) // Custom error handler
}

// DefaultAuthConfig returns a default authentication configuration
func DefaultAuthConfig(service Service) *AuthConfig {
	return &AuthConfig{
		Service:      service,
		CookieName:   "jwt",
		APIKeyHeader: "X-Api-Key",
		RequireAuth:  true,
		ErrorHandler: defaultErrorHandler,
	}
}

// defaultErrorHandler provides a default error response
func defaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
}

// getRequiredOIDCConfig returns the global OIDC config or panics if not set
func getRequiredOIDCConfig() *OAuthConfig {
	if globalOAuthConfig == nil {
		panic("OAuth configuration not set. Call user.SetOAuthConfig() before using authentication middleware or SetupAuthRoutes()")
	}
	return globalOAuthConfig
}

// validateAPIKey validates an API key and returns claims
func validateAPIKey(ctx context.Context, service Service, apiKey string) (*Claims, error) {
	user, err := service.ValidateAPIKey(ctx, apiKey)
	if err != nil {
		return nil, fmt.Errorf("invalid api key")
	}

	// Create claims from user data
	claims := &Claims{
		Sub:        user.ID,
		Email:      user.Email,
		GivenName:  user.GivenName,
		FamilyName: user.FamilyName,
		Picture:    user.Picture,
		Username:   user.Email, // Use email as username for API key auth
		APIKey:     apiKey,
		Role:       user.Role,
		Provider:   "api_key",
	}

	return claims, nil
}

// RequireAuthMiddleware creates middleware that requires authentication via JWT or API key
// Everything is initialized internally - no configuration needed
func RequireAuthMiddleware() func(http.Handler) http.Handler {
	// Create user service internally (same pattern as in SetupAuthRoutes)
	repo := NewSQLiteRepository()
	userService := NewService(repo)

	// Create default auth config
	config := DefaultAuthConfig(userService)
	config.RequireAuth = true

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var claims *Claims
			var user *User
			var err error

			// First try JWT cookie with OIDC validation
			cookie, cookieErr := r.Cookie(config.CookieName)
			if cookieErr == nil {
				oidcConfig := getRequiredOIDCConfig()
				claims, err = ValidateOIDCTokenFromOAuthConfig(r.Context(), cookie.Value, oidcConfig)
				if err == nil && claims != nil {
					// JWT is valid, get user data
					user, err = config.Service.GetUserByEmail(r.Context(), claims.Email)
					if err == nil {
						// Priority 1: Use API key from JWT claims (Cognito)
						if claims.APIKey != "" {
							// Sync JWT key with database if different
							if user.APIKey != claims.APIKey {
								err := config.Service.UpdateAPIKey(r.Context(), user.Email, user.Email, claims.APIKey)
								if err == nil {
									user.APIKey = claims.APIKey
								}
							}
						} else if user.APIKey != "" {
							// Priority 2: Use API key from database
							claims.APIKey = user.APIKey
						} else {
							// Priority 3: Generate new API key if both are empty
							apiKey, err := config.Service.GenerateAPIKey(r.Context(), user.Email, user.Email)
							if err == nil {
								user.APIKey = apiKey
								claims.APIKey = apiKey
							}
						}

						// Add user to context and proceed
						ctx := context.WithValue(r.Context(), ClaimsKey, claims)
						ctx = context.WithValue(ctx, UserKey, user)
						next.ServeHTTP(w, r.WithContext(ctx))
						return
					}
				}
			}

			// Fallback to API key header
			apiKey := r.Header.Get(config.APIKeyHeader)
			if apiKey != "" {
				claims, err = validateAPIKey(r.Context(), config.Service, apiKey)
				if err == nil && claims != nil {
					// API key is valid, get user data
					user, err = config.Service.GetUserByEmail(r.Context(), claims.Email)
					if err == nil {
						// Add claims and user to context and proceed
						ctx := context.WithValue(r.Context(), ClaimsKey, claims)
						ctx = context.WithValue(ctx, UserKey, user)
						next.ServeHTTP(w, r.WithContext(ctx))
						return
					}
				}
			}

			// If we get here, authentication failed
			if config.RequireAuth {
				config.ErrorHandler(w, r, fmt.Errorf("no valid authentication provided"))
				return
			}

			// Optional auth - proceed without user context
			next.ServeHTTP(w, r)
		})
	}
}

// OptionalAuthMiddleware creates middleware that allows optional authentication
// Everything is initialized internally - no configuration needed
func OptionalAuthMiddleware() func(http.Handler) http.Handler {
	// Create user service internally (same pattern as in SetupAuthRoutes)
	repo := NewSQLiteRepository()
	userService := NewService(repo)

	// Create default auth config with optional auth
	config := DefaultAuthConfig(userService)
	config.RequireAuth = false

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var claims *Claims
			var user *User
			var err error

			// First try JWT cookie with OIDC validation
			cookie, cookieErr := r.Cookie(config.CookieName)
			if cookieErr == nil {
				oidcConfig := getRequiredOIDCConfig()
				claims, err = ValidateOIDCTokenFromOAuthConfig(r.Context(), cookie.Value, oidcConfig)
				if err == nil && claims != nil {
					// JWT is valid, get user data
					user, err = config.Service.GetUserByEmail(r.Context(), claims.Email)
					if err == nil {
						// Priority 1: Use API key from JWT claims (Cognito)
						if claims.APIKey != "" {
							// Sync JWT key with database if different
							if user.APIKey != claims.APIKey {
								err := config.Service.UpdateAPIKey(r.Context(), user.Email, user.Email, claims.APIKey)
								if err == nil {
									user.APIKey = claims.APIKey
								}
							}
						} else if user.APIKey != "" {
							// Priority 2: Use API key from database
							claims.APIKey = user.APIKey
						} else {
							// Priority 3: Generate new API key if both are empty
							apiKey, err := config.Service.GenerateAPIKey(r.Context(), user.Email, user.Email)
							if err == nil {
								user.APIKey = apiKey
								claims.APIKey = apiKey
							}
						}

						// Add user to context and proceed
						ctx := context.WithValue(r.Context(), ClaimsKey, claims)
						ctx = context.WithValue(ctx, UserKey, user)
						next.ServeHTTP(w, r.WithContext(ctx))
						return
					}
				}
			}

			// Fallback to API key header
			apiKey := r.Header.Get(config.APIKeyHeader)
			if apiKey != "" {
				claims, err = validateAPIKey(r.Context(), config.Service, apiKey)
				if err == nil && claims != nil {
					// API key is valid, get user data
					user, err = config.Service.GetUserByEmail(r.Context(), claims.Email)
					if err == nil {
						// Add claims and user to context and proceed
						ctx := context.WithValue(r.Context(), ClaimsKey, claims)
						ctx = context.WithValue(ctx, UserKey, user)
						next.ServeHTTP(w, r.WithContext(ctx))
						return
					}
				}
			}

			// If we get here, authentication failed
			if config.RequireAuth {
				config.ErrorHandler(w, r, fmt.Errorf("no valid authentication provided"))
				return
			}

			// Optional auth - proceed without user context
			next.ServeHTTP(w, r)
		})
	}
}

// APIKeyOnlyMiddleware creates middleware that only accepts API key authentication
// Everything is initialized internally - no configuration needed
func APIKeyOnlyMiddleware() func(http.Handler) http.Handler {
	// Create user service internally
	repo := NewSQLiteRepository()
	userService := NewService(repo)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only try API key authentication (no JWT)
			apiKey := r.Header.Get("X-Api-Key")
			if apiKey != "" {
				claims, err := validateAPIKey(r.Context(), userService, apiKey)
				if err == nil && claims != nil {
					// API key is valid, get user data
					user, err := userService.GetUserByEmail(r.Context(), claims.Email)
					if err == nil {
						// Add claims and user to context and proceed
						ctx := context.WithValue(r.Context(), ClaimsKey, claims)
						ctx = context.WithValue(ctx, UserKey, user)
						next.ServeHTTP(w, r.WithContext(ctx))
						return
					}
				}
			}

			// Authentication failed
			defaultErrorHandler(w, r, fmt.Errorf("valid API key required"))
		})
	}
}

// GetUserFromContext extracts the authenticated user from the request context
func GetUserFromContext(r *http.Request) (*User, bool) {
	user, ok := r.Context().Value(UserKey).(*User)
	return user, ok
}

// GetClaimsFromContext extracts the authentication claims from the request context
func GetClaimsFromContext(r *http.Request) (*Claims, bool) {
	claims, ok := r.Context().Value(ClaimsKey).(*Claims)
	return claims, ok
}

// GetUserIDFromContext extracts the user ID from the request context
func GetUserIDFromContext(r *http.Request) (string, bool) {
	if claims, ok := GetClaimsFromContext(r); ok {
		// Note: Use email instead of Sub since user ID is now email-based
		return claims.Email, true
	}
	return "", false
}

// MustGetUserFromContext extracts the user from context or panics (use in authenticated routes)
func MustGetUserFromContext(r *http.Request) *User {
	user, ok := GetUserFromContext(r)
	if !ok {
		panic("user not found in context - ensure authentication middleware is applied")
	}
	return user
}

// MustGetUserIDFromContext extracts the user ID from context or panics (use in authenticated routes)
func MustGetUserIDFromContext(r *http.Request) string {
	userID, ok := GetUserIDFromContext(r)
	if !ok {
		panic("user ID not found in context - ensure authentication middleware is applied")
	}
	return userID
}

// Chi route parameter helpers (generic helpers for common patterns)

// GetIDFromURL extracts id parameter from Chi URL
func GetIDFromURL(r *http.Request) string {
	return chi.URLParam(r, "id")
}

// GetEmailFromURL extracts email parameter from Chi URL
func GetEmailFromURL(r *http.Request) string {
	return chi.URLParam(r, "email")
}
