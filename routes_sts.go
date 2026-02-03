package user

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// SetupSTSRoutes registers STS credential exchange routes.
func SetupSTSRoutes(r chi.Router) {
	r.Group(func(r chi.Router) {
		r.Use(RequireAuthMiddleware())
		r.Get("/api/auth/sts-credentials", handleSTSCredentials)
	})
}

// handleSTSCredentials exchanges a Cognito ID token for temporary AWS credentials.
func handleSTSCredentials(w http.ResponseWriter, r *http.Request) {
	// Get the ID token from the cookie
	cookie, err := r.Cookie("id_token")
	if err != nil || cookie.Value == "" {
		log.Printf("STS: No ID token cookie found: %v", err)
		writeSTSError(w, "ID token not found", http.StatusUnauthorized)
		return
	}

	// Get OAuth config
	config := GetOAuthConfig()
	if config == nil {
		log.Printf("STS: OAuth config not set")
		writeSTSError(w, "Server configuration error", http.StatusInternalServerError)
		return
	}

	// Note: STSRoleARN is no longer required - role can come from JWT token's cognito:preferred_role claim.
	// This allows dynamic role selection based on Cognito group membership.

	// Exchange ID token for STS credentials
	creds, err := GetSTSCredentials(r.Context(), cookie.Value, config)
	if err != nil {
		log.Printf("STS: Failed to get credentials: %v", err)
		writeSTSError(w, "Failed to obtain credentials", http.StatusInternalServerError)
		return
	}

	log.Printf("STS: Issued credentials expiring at %s", creds.Expiration.Format("2006-01-02T15:04:05Z"))

	// Return credentials as JSON
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(creds)
}

// writeSTSError writes an error response for STS endpoints.
func writeSTSError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
