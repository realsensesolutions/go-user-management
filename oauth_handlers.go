package user

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Constants for retry attempt management
const (
	MaxOAuthRetryAttempts = 3
	RetryQueryParam       = "oauth_retry"
)

// OAuth2Handlers provides HTTP handlers for OAuth2 flow
type OAuth2Handlers struct {
	oauth2Service   *OAuth2Service
	cognitoConfig   *CognitoConfig
	getFrontEndURL  func() string
	getCookieDomain func() string
	createJWTCookie func(token string, maxAge int, domain string) string
}

// NewOAuth2Handlers creates a new OAuth2 handlers instance
func NewOAuth2Handlers(service *OAuth2Service, cognitoConfig *CognitoConfig, frontEndURL, cookieDomain func() string, createJWTCookie func(string, int, string) string) *OAuth2Handlers {
	return &OAuth2Handlers{
		oauth2Service:   service,
		cognitoConfig:   cognitoConfig,
		getFrontEndURL:  frontEndURL,
		getCookieDomain: cookieDomain,
		createJWTCookie: createJWTCookie,
	}
}

// LoginHandler handles OIDC login requests
func (h *OAuth2Handlers) LoginHandler(w http.ResponseWriter, r *http.Request) {
	// Extract redirect URL from query parameters
	redirectURL := r.URL.Query().Get("redirect_url")

	// Generate OAuth authorization URL
	authURL, err := h.oauth2Service.GenerateAuthURL(redirectURL)
	if err != nil {
		log.Printf("❌ Failed to generate OAuth authorization URL: %v", err)
		h.writeJSONError(w, http.StatusInternalServerError, "Failed to generate authorization URL")
		return
	}

	w.Header().Set("Location", authURL)
	w.WriteHeader(http.StatusFound)
}

// CallbackHandler handles OIDC callback requests
func (h *OAuth2Handlers) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	// Extract code and state from query parameters
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" {
		log.Printf("❌ Missing authorization code")
		h.writeJSONError(w, http.StatusBadRequest, "Missing authorization code")
		return
	}

	if state == "" {
		log.Printf("❌ Missing state parameter")
		h.writeJSONError(w, http.StatusBadRequest, "Missing state parameter")
		return
	}

	// Handle OAuth2 callback
	_, rawIDToken, redirectURL, err := h.oauth2Service.HandleCallback(code, state)
	if err != nil {
		log.Printf("❌ OAuth2 callback failed: %v", err)

		// Check retry attempts to prevent infinite loops
		retryAttempts := h.getRetryAttempts(r)
		if h.hasExceededRetryLimit(retryAttempts) {
			log.Printf("❌ Exceeded maximum OAuth retry attempts (%d), falling back to error", MaxOAuthRetryAttempts)
			h.writeJSONError(w, http.StatusBadRequest, "Authentication failed: too many retry attempts")
			return
		}

		// Extract original redirect URL from current request
		originalRedirectURL := r.URL.Query().Get("redirect_url")
		if originalRedirectURL == "" {
			// Default to dashboard if no redirect URL is available
			originalRedirectURL = h.getFrontEndURL() + "/dashboard"
		}

		// Generate new OAuth authorization URL with retry tracking
		authURL, authErr := h.oauth2Service.GenerateAuthURL(originalRedirectURL)
		if authErr != nil {
			log.Printf("❌ Failed to generate retry OAuth authorization URL: %v", authErr)
			h.writeJSONError(w, http.StatusInternalServerError, "Failed to restart authentication")
			return
		}

		// Add retry attempt tracking to the URL
		retryAttempts++
		authURL += fmt.Sprintf("&%s=%d", RetryQueryParam, retryAttempts)

		log.Printf("🔄 Redirecting to OAuth authorize endpoint (attempt %d/%d): %s", retryAttempts, MaxOAuthRetryAttempts, authURL)
		w.Header().Set("Location", authURL)
		w.WriteHeader(http.StatusFound)
		return
	}

	// Use the real raw ID token from Cognito (not a fake one!)

	// Create JWT cookie using the real Cognito ID token
	maxAge := h.extractJWTExpiration(rawIDToken)
	cookieDomain := h.getCookieDomain()
	cookie := h.createJWTCookie(rawIDToken, maxAge, cookieDomain)

	log.Printf("🍪 Setting JWT cookie with Max-Age: %d seconds", maxAge)

	// Set cookie and redirect
	w.Header().Set("Set-Cookie", cookie)

	// Use the redirect URL from state, or default to dashboard
	finalRedirectURL := redirectURL
	if finalRedirectURL == "" {
		finalRedirectURL = h.getFrontEndURL() + "/dashboard"
	}

	log.Printf("🔗 Redirecting after OAuth success to: %s", finalRedirectURL)
	w.Header().Set("Location", finalRedirectURL)
	w.WriteHeader(http.StatusFound)
}

// LogoutHandler handles logout requests with Cognito logout URL support
func (h *OAuth2Handlers) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// Clear the JWT cookie
	cookieDomain := h.getCookieDomain()
	clearCookie := h.createJWTCookie("", 0, cookieDomain)

	// Get redirect URL from query parameter, default to frontend home
	redirectURL := r.URL.Query().Get("redirect_url")
	if redirectURL == "" {
		redirectURL = h.getFrontEndURL()
	}

	// Set the clear cookie header
	w.Header().Set("Set-Cookie", clearCookie)

	// If Cognito domain is configured, use Cognito logout URL
	if h.cognitoConfig.Domain != "" && h.cognitoConfig.ClientID != "" {
		// URL encode the redirect URL to ensure it's properly formatted
		encodedRedirectURL := url.QueryEscape(redirectURL)

		// Construct Cognito logout URL
		logoutURL := fmt.Sprintf("%s/logout?client_id=%s&logout_uri=%s",
			h.cognitoConfig.Domain, h.cognitoConfig.ClientID, encodedRedirectURL)

		log.Printf("🔗 Redirecting to Cognito logout: %s", logoutURL)
		w.Header().Set("Location", logoutURL)
		w.WriteHeader(http.StatusFound)
		return
	}

	// Simple logout - just clear cookie and redirect to specified URL
	w.Header().Set("Location", redirectURL)
	w.WriteHeader(http.StatusFound)
}

// Helper methods

// writeJSONError writes a JSON error response
func (h *OAuth2Handlers) writeJSONError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	fmt.Fprintf(w, `{"error": "%s"}`, message)
}

// getRetryAttempts extracts retry attempt count from query parameters
func (h *OAuth2Handlers) getRetryAttempts(r *http.Request) int {
	retryStr := r.URL.Query().Get(RetryQueryParam)
	if retryStr == "" {
		return 0
	}

	attempts, err := strconv.Atoi(retryStr)
	if err != nil {
		return 0
	}

	return attempts
}

// hasExceededRetryLimit checks if the retry attempts exceed the maximum allowed
func (h *OAuth2Handlers) hasExceededRetryLimit(attempts int) bool {
	return attempts >= MaxOAuthRetryAttempts
}

// extractJWTExpiration extracts the exp claim from a JWT token to set cookie maxAge
func (h *OAuth2Handlers) extractJWTExpiration(tokenString string) int {
	// Simple JWT parsing to extract exp claim without full validation
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		log.Printf("⚠️ Invalid JWT format, using default maxAge")
		return 3600 // Default 1 hour
	}

	// Decode payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		log.Printf("⚠️ Failed to decode JWT payload, using default maxAge: %v", err)
		return 3600 // Default 1 hour
	}

	// Parse JSON to extract exp claim
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		log.Printf("⚠️ Failed to parse JWT payload, using default maxAge: %v", err)
		return 3600 // Default 1 hour
	}

	// Extract exp claim
	if exp, ok := claims["exp"].(float64); ok {
		maxAge := int(exp - float64(time.Now().Unix()))
		if maxAge > 0 {
			return maxAge
		}
	}

	log.Printf("⚠️ No valid exp claim found, using default maxAge")
	return 3600 // Default 1 hour
}
