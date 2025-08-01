package user

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
)

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

// OIDCTokenValidator represents a function that can validate OIDC/JWT tokens
// This allows projects to inject their own JWT validation logic
type OIDCTokenValidator func(ctx context.Context, tokenString string) (*Claims, error)

// AuthConfig holds configuration for authentication middleware
type AuthConfig struct {
	Service       Service                                                 // User service for API key validation
	OIDCValidator OIDCTokenValidator                                      // Optional JWT token validator
	CookieName    string                                                  // JWT cookie name (default: "jwt")
	APIKeyHeader  string                                                  // API key header name (default: "X-Api-Key")
	RequireAuth   bool                                                    // Whether auth is required (default: true)
	ErrorHandler  func(w http.ResponseWriter, r *http.Request, err error) // Custom error handler
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

// validateAPIKey validates an API key and returns claims
func validateAPIKey(ctx context.Context, service Service, apiKey string) (*Claims, error) {
	fmt.Printf("🔍 [API_KEY_VALIDATION] Validating API key: '%s'\n", apiKey)

	user, err := service.ValidateAPIKey(ctx, apiKey)
	if err != nil {
		fmt.Printf("❌ [API_KEY_VALIDATION] API key validation failed: %v\n", err)
		return nil, fmt.Errorf("invalid api key")
	}

	fmt.Printf("✅ [API_KEY_VALIDATION] API key valid, user found: ID='%s', Email='%s'\n", user.ID, user.Email)

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

	fmt.Printf("🔍 [API_KEY_VALIDATION] Created claims: Sub='%s', Email='%s', Username='%s'\n",
		claims.Sub, claims.Email, claims.Username)

	return claims, nil
}

// RequireAuthMiddleware creates middleware that requires authentication via JWT or API key
func RequireAuthMiddleware(config *AuthConfig) func(http.Handler) http.Handler {
	if config == nil {
		panic("auth config is required")
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var claims *Claims
			var user *User
			var err error

			fmt.Printf("🔍 [AUTH_MIDDLEWARE] Processing request: %s %s\n", r.Method, r.URL.Path)

			// First try JWT cookie if validator is provided
			if config.OIDCValidator != nil {
				cookie, cookieErr := r.Cookie(config.CookieName)
				if cookieErr == nil {
					fmt.Printf("🔍 [AUTH_MIDDLEWARE] Found JWT cookie, validating...\n")
					claims, err = config.OIDCValidator(r.Context(), cookie.Value)
					if err == nil && claims != nil {
						fmt.Printf("✅ [AUTH_MIDDLEWARE] JWT valid, getting user by email: '%s'\n", claims.Email)
						// JWT is valid, get user data
						user, err = config.Service.GetUserByEmail(r.Context(), claims.Email)
						if err == nil {
							fmt.Printf("✅ [AUTH_MIDDLEWARE] User found via JWT, checking API key priority\n")

							// Priority 1: Use API key from JWT claims (Cognito)
							if claims.APIKey != "" {
								fmt.Printf("✅ [AUTH_MIDDLEWARE] Using API key from JWT claims: '%s'\n", claims.APIKey)
								// Sync JWT key with database if different
								if user.APIKey != claims.APIKey {
									fmt.Printf("🔄 [AUTH_MIDDLEWARE] Syncing JWT API key to database\n")
									err := config.Service.UpdateAPIKey(r.Context(), user.Email, user.Email, claims.APIKey)
									if err != nil {
										fmt.Printf("⚠️ [AUTH_MIDDLEWARE] Failed to sync API key to DB: %v\n", err)
									} else {
										user.APIKey = claims.APIKey
									}
								}
							} else if user.APIKey != "" {
								// Priority 2: Use API key from database
								fmt.Printf("✅ [AUTH_MIDDLEWARE] Using API key from database: '%s'\n", user.APIKey)
								claims.APIKey = user.APIKey
							} else {
								// Priority 3: Generate new API key if both are empty
								fmt.Printf("🔍 [AUTH_MIDDLEWARE] No API key found, generating new one for user: '%s'\n", user.Email)
								apiKey, err := config.Service.GenerateAPIKey(r.Context(), user.Email, user.Email)
								if err != nil {
									fmt.Printf("❌ [AUTH_MIDDLEWARE] Failed to generate API key: %v\n", err)
								} else {
									fmt.Printf("✅ [AUTH_MIDDLEWARE] Generated new API key: '%s'\n", apiKey)
									user.APIKey = apiKey
									claims.APIKey = apiKey
								}
							}

							// Add user to context and proceed
							ctx := context.WithValue(r.Context(), ClaimsKey, claims)
							ctx = context.WithValue(ctx, UserKey, user)
							next.ServeHTTP(w, r.WithContext(ctx))
							return
						} else {
							fmt.Printf("❌ [AUTH_MIDDLEWARE] Failed to get user by ID '%s': %v\n", claims.Email, err)
						}
					} else {
						fmt.Printf("❌ [AUTH_MIDDLEWARE] JWT validation failed: %v\n", err)
					}
				} else {
					fmt.Printf("🔍 [AUTH_MIDDLEWARE] No JWT cookie found: %v\n", cookieErr)
				}
			}

			// Fallback to API key header
			apiKey := r.Header.Get(config.APIKeyHeader)
			if apiKey != "" {
				fmt.Printf("🔍 [AUTH_MIDDLEWARE] Found API key header, validating...\n")
				claims, err = validateAPIKey(r.Context(), config.Service, apiKey)
				if err == nil && claims != nil {
					fmt.Printf("✅ [AUTH_MIDDLEWARE] API key valid, getting user by email: '%s'\n", claims.Email)
					// API key is valid, get user data
					user, err = config.Service.GetUserByEmail(r.Context(), claims.Email)
					if err == nil {
						fmt.Printf("✅ [AUTH_MIDDLEWARE] User found via API key, proceeding\n")
						// Add claims and user to context and proceed
						ctx := context.WithValue(r.Context(), ClaimsKey, claims)
						ctx = context.WithValue(ctx, UserKey, user)
						next.ServeHTTP(w, r.WithContext(ctx))
						return
					} else {
						fmt.Printf("❌ [AUTH_MIDDLEWARE] Failed to get user by ID '%s': %v\n", claims.Email, err)
					}
				} else {
					fmt.Printf("❌ [AUTH_MIDDLEWARE] API key validation failed: %v\n", err)
				}
			} else {
				fmt.Printf("🔍 [AUTH_MIDDLEWARE] No API key header found\n")
			}

			// If we get here, authentication failed
			fmt.Printf("❌ [AUTH_MIDDLEWARE] Authentication failed, returning 401\n")
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
func OptionalAuthMiddleware(config *AuthConfig) func(http.Handler) http.Handler {
	config.RequireAuth = false
	return RequireAuthMiddleware(config)
}

// APIKeyOnlyMiddleware creates middleware that only accepts API key authentication
func APIKeyOnlyMiddleware(service Service) func(http.Handler) http.Handler {
	config := DefaultAuthConfig(service)
	config.OIDCValidator = nil // Disable JWT validation

	return RequireAuthMiddleware(config)
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
