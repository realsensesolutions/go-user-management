package user

import (
	"context"
	"log"
	"net/http"
	"strings"

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
	UserRole   string `json:"custom:userRole"` // User role from Cognito custom attribute
	Provider   string `json:"provider"`    // Auth provider (jwt, api_key)
}

// getRequiredOIDCConfig returns the global OIDC config or panics if not set
func getRequiredOIDCConfig() *OAuthConfig {
	if oauthConfig == nil {
		panic("OAuth configuration not set. Call user.SetOAuthConfig() before using authentication middleware or SetupAuthRoutes()")
	}
	return oauthConfig
}

// AuthConfig, DefaultAuthConfig, validateAPIKey removed
// These were used by OptionalAuthMiddleware and APIKeyOnlyMiddleware which required
// SQLite database access. Use RequireAuthMiddleware() instead for JWT/Cognito auth.

// RequireAuthMiddleware creates middleware that requires authentication
// Supports both JWT tokens (from cookie) and opaque tokens (from Authorization header)
// No database operations - validates JWT tokens or looks up users in Cognito by token
func RequireAuthMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("🔍 [RequireAuthMiddleware] === Authentication Check Started ===")
			log.Printf("🔍 [RequireAuthMiddleware] Request Method: %s, Path: %s", r.Method, r.URL.Path)
			log.Printf("🔍 [RequireAuthMiddleware] Request Host: %s", r.Host)

			var claims *Claims
			var err error

			// First, try JWT cookie with OIDC validation
			cookie, cookieErr := r.Cookie("jwt")
			if cookieErr == nil {
				log.Printf("🔍 [RequireAuthMiddleware] Found JWT cookie: jwt (length: %d)", len(cookie.Value))
				oidcConfig := getRequiredOIDCConfig()
				log.Printf("🔄 [RequireAuthMiddleware] Validating JWT token...")
				claims, err = ValidateOIDCTokenFromOAuthConfig(r.Context(), cookie.Value, oidcConfig)
				if err == nil && claims != nil {
					log.Printf("✅ [RequireAuthMiddleware] JWT token validated successfully")
					log.Printf("🔍 [RequireAuthMiddleware] Claims - Email: %s, Username: %s, Sub: %s", claims.Email, claims.Username, claims.Sub)

					// JWT is valid - add claims to context and proceed
					log.Printf("✅ [RequireAuthMiddleware] Authentication successful, proceeding to handler")
					ctx := context.WithValue(r.Context(), ClaimsKey, claims)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				} else {
					log.Printf("❌ [RequireAuthMiddleware] JWT token validation failed: %v", err)
					log.Printf("🔍 [RequireAuthMiddleware] Error type: %T", err)
				}
			} else {
				log.Printf("⚠️ [RequireAuthMiddleware] No JWT cookie found: %v", cookieErr)
			}

			// Second, try Authorization header with opaque token
			authHeader := r.Header.Get("Authorization")
			if authHeader != "" {
				parts := strings.SplitN(authHeader, " ", 2)
				if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
					token := parts[1]
					log.Printf("🔍 [RequireAuthMiddleware] Found Authorization header with Bearer token (length: %d)", len(token))

					// Check if it's a JWT (has 3 dot-separated parts) or opaque token
					if isJWTToken(token) {
						log.Printf("🔄 [RequireAuthMiddleware] Token appears to be JWT, validating...")
						oidcConfig := getRequiredOIDCConfig()
						claims, err = ValidateOIDCTokenFromOAuthConfig(r.Context(), token, oidcConfig)
						if err == nil && claims != nil {
							log.Printf("✅ [RequireAuthMiddleware] JWT token from Authorization header validated successfully")
							ctx := context.WithValue(r.Context(), ClaimsKey, claims)
							next.ServeHTTP(w, r.WithContext(ctx))
							return
						} else {
							log.Printf("❌ [RequireAuthMiddleware] JWT token from Authorization header validation failed: %v", err)
						}
					} else {
						// Opaque token - look up in Cognito
						log.Printf("🔄 [RequireAuthMiddleware] Token appears to be opaque, looking up in Cognito...")
						claims, err = FindUserByToken(r.Context(), token)
						if err == nil && claims != nil {
							log.Printf("✅ [RequireAuthMiddleware] Opaque token validated successfully")
							log.Printf("🔍 [RequireAuthMiddleware] Claims - Email: %s, Username: %s", claims.Email, claims.Username)
							ctx := context.WithValue(r.Context(), ClaimsKey, claims)
							next.ServeHTTP(w, r.WithContext(ctx))
							return
						} else {
							log.Printf("❌ [RequireAuthMiddleware] Opaque token lookup failed: %v", err)
						}
					}
				}
			}

			// Authentication failed
			log.Printf("❌ [RequireAuthMiddleware] === Authentication Failed ===")
			log.Printf("❌ [RequireAuthMiddleware] No valid authentication token provided")
			http.Error(w, "Unauthorized: no valid authentication token provided", http.StatusUnauthorized)
		})
	}
}

func isJWTToken(token string) bool {
	parts := strings.Split(token, ".")
	return len(parts) == 3
}

// OptionalAuthMiddleware and APIKeyOnlyMiddleware removed
// These middleware functions required SQLite database access which is no longer supported.
// Use RequireAuthMiddleware() instead, which supports JWT and Cognito token authentication.

// GetUserFromContext extracts the authenticated user from the request context
// It builds a User from Claims stored in context
func GetUserFromContext(r *http.Request) (*User, bool) {
	claims, ok := GetClaimsFromContext(r)
	if !ok {
		return nil, false
	}

	user := &User{
		Email:      claims.Email,
		GivenName:  claims.GivenName,
		FamilyName: claims.FamilyName,
		Picture:    claims.Picture,
		Role:       claims.Role,
		APIKey:     claims.APIKey,
	}

	return user, true
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
