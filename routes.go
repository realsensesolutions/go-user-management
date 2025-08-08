package user

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"

	"github.com/go-chi/chi/v5"
)

// ErrorResponse represents a standard error response
type ErrorResponse struct {
	Error   string            `json:"error"`
	Details map[string]string `json:"details,omitempty"`
}

// UserResponse represents a user response for API endpoints
type UserResponse struct {
	ID         string `json:"id"`
	Email      string `json:"email,omitempty"` // Omitted in some contexts for privacy
	GivenName  string `json:"givenName"`
	FamilyName string `json:"familyName"`
	Picture    string `json:"picture"`
	Role       string `json:"role"`
	CreatedAt  string `json:"createdAt"`
	UpdatedAt  string `json:"updatedAt"`
}

// convertUserToResponse converts internal User to API response format
func convertUserToResponse(u *User, includeEmail bool) *UserResponse {
	resp := &UserResponse{
		ID:         u.ID,
		GivenName:  u.GivenName,
		FamilyName: u.FamilyName,
		Picture:    u.Picture,
		Role:       u.Role,
		CreatedAt:  u.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:  u.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	if includeEmail {
		resp.Email = u.ID // ID is the email address in the new schema
	}

	return resp
}

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

// RegisterUserRoutes registers standard user management routes
func RegisterUserRoutes(r chi.Router) {
	// Create user service internally using SQLite repository
	repo := NewSQLiteRepository()
	service := NewService(repo)

	// Apply authentication middleware to user routes
	r.Route("/api/users", func(r chi.Router) {
		r.Use(RequireAuthMiddleware())

		// GET /api/users/me - Get current user profile
		r.Get("/me", getCurrentUserHandler(service))

		// GET /api/users/{id} - Get user by ID (admin only or self)
		r.Get("/{id}", getUserByIDHandler(service))

		// PUT /api/users/me - Update current user profile
		r.Put("/me", updateCurrentUserHandler(service))

		// POST /api/users/api-key - Generate new API key for current user
		r.Post("/api-key", generateAPIKeyHandler(service))

		// GET /api/users/api-key - Get current API key for current user
		r.Get("/api-key", getAPIKeyHandler(service))

		// GET /api/users - List users (admin only)
		r.Get("/", listUsersHandler(service, false)) // Default to not include email for privacy
	})
}

// getCurrentUserHandler returns the current authenticated user
func getCurrentUserHandler(service Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := MustGetUserFromContext(r)
		response := convertUserToResponse(user, true) // Include email for own profile
		writeJSON(w, http.StatusOK, response)
	}
}

// getUserByIDHandler returns a user by ID (with access control)
func getUserByIDHandler(service Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestedUserID := chi.URLParam(r, "id")
		currentUser := MustGetUserFromContext(r)

		// Users can only access their own profile unless they're admin
		if currentUser.ID != requestedUserID && currentUser.Role != "admin" {
			writeError(w, http.StatusForbidden, "Access denied", map[string]string{
				"reason": "Can only access your own profile",
			})
			return
		}

		user, err := service.GetUserByID(r.Context(), requestedUserID)
		if err != nil {
			if err == ErrUserNotFound {
				writeError(w, http.StatusNotFound, "User not found", nil)
			} else {
				writeError(w, http.StatusInternalServerError, "Failed to retrieve user", nil)
			}
			return
		}

		// Include email only if accessing own profile or user is admin
		includeEmail := currentUser.ID == requestedUserID || currentUser.Role == "admin"
		response := convertUserToResponse(user, includeEmail)
		writeJSON(w, http.StatusOK, response)
	}
}

// updateCurrentUserHandler updates the current user's profile
func updateCurrentUserHandler(service Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		currentUser := MustGetUserFromContext(r)

		var updateReq UpdateUserRequest
		if err := json.NewDecoder(r.Body).Decode(&updateReq); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid request body", map[string]string{
				"error": err.Error(),
			})
			return
		}

		// Set the user ID to current user (prevent privilege escalation)
		updateReq.ID = currentUser.ID

		updatedUser, err := service.UpdateUser(r.Context(), updateReq)
		if err != nil {
			if err == ErrUserNotFound {
				writeError(w, http.StatusNotFound, "User not found", nil)
			} else {
				writeError(w, http.StatusInternalServerError, "Failed to update user", map[string]string{
					"error": err.Error(),
				})
			}
			return
		}

		response := convertUserToResponse(updatedUser, true) // Include email for own profile
		writeJSON(w, http.StatusOK, response)
	}
}

// generateAPIKeyHandler generates a new API key for the current user
func generateAPIKeyHandler(service Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		currentUser := MustGetUserFromContext(r)

		apiKey, err := service.GenerateAPIKey(r.Context(), currentUser.ID, currentUser.Email)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to generate API key", map[string]string{
				"error": err.Error(),
			})
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{
			"apiKey": apiKey,
		})
	}
}

// getAPIKeyHandler returns the current API key for the user
func getAPIKeyHandler(service Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		currentUser := MustGetUserFromContext(r)

		apiKey, err := service.GetAPIKey(r.Context(), currentUser.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to retrieve API key", map[string]string{
				"error": err.Error(),
			})
			return
		}

		if apiKey == "" {
			writeError(w, http.StatusNotFound, "No API key found", map[string]string{
				"message": "Use POST /api/users/api-key to generate one",
			})
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{
			"apiKey": apiKey,
		})
	}
}

// listUsersHandler lists users (admin only)
func listUsersHandler(service Service, includeEmail bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		currentUser := MustGetUserFromContext(r)

		// Only admins can list users
		if currentUser.Role != "admin" {
			writeError(w, http.StatusForbidden, "Access denied", map[string]string{
				"reason": "Admin role required",
			})
			return
		}

		// Parse query parameters
		limitStr := r.URL.Query().Get("limit")
		offsetStr := r.URL.Query().Get("offset")

		limit := 50 // Default limit
		if limitStr != "" {
			if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 && parsed <= 100 {
				limit = parsed
			}
		}

		offset := 0 // Default offset
		if offsetStr != "" {
			if parsed, err := strconv.Atoi(offsetStr); err == nil && parsed >= 0 {
				offset = parsed
			}
		}

		users, err := service.ListUsers(r.Context(), limit, offset)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to list users", map[string]string{
				"error": err.Error(),
			})
			return
		}

		// Convert users to response format
		var responses []*UserResponse
		for _, user := range users {
			responses = append(responses, convertUserToResponse(user, includeEmail))
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"users":  responses,
			"limit":  limit,
			"offset": offset,
			"count":  len(responses),
		})
	}
}

// SetupAuthRoutes sets up all authentication routes using the provided OAuthConfig
// This is the main entry point that replaces the complex manual setup
func SetupAuthRoutes(r chi.Router, config OAuthConfig) error {
	// Validate configuration
	if err := validateOAuthConfig(&config); err != nil {
		return fmt.Errorf("invalid OAuth configuration: %w", err)
	}

	// Create user service using SQLite (for now, could be configurable later)
	repo := NewSQLiteRepository()
	userService := NewService(repo)

	// Create state repository
	stateRepo := NewSQLiteStateRepository()

	// Create OAuth2 service using the consolidated config
	oauth2Service, err := createOAuth2ServiceFromOAuthConfig(userService, stateRepo, &config)
	if err != nil {
		return fmt.Errorf("failed to create OAuth2 service: %w", err)
	}

	// Create OAuth2 handlers with internal helper functions
	oauth2Handlers := createOAuth2HandlersFromOAuthConfig(oauth2Service, &config)

	// Setup authentication routes
	r.Get("/oauth2/idpresponse", oauth2Handlers.CallbackHandler)
	r.Get("/api/auth/login", oauth2Handlers.LoginHandler)
	r.Get("/api/auth/logout", oauth2Handlers.LogoutHandler)

	// Setup protected auth routes (requires authentication)
	r.Route("/api/auth", func(r chi.Router) {
		// Authentication middleware - everything handled internally
		r.Use(RequireAuthMiddleware())
		r.Get("/profile", createProfileHandler(userService))
	})

	log.Printf("✅ Authentication routes setup completed")
	return nil
}

// createOAuth2ServiceFromOAuthConfig creates OAuth2Service from OAuthConfig
func createOAuth2ServiceFromOAuthConfig(userService Service, stateRepo StateRepository, config *OAuthConfig) (*OAuth2Service, error) {
	// Create OAuth2 service directly from OAuthConfig - no need for legacy conversion
	return NewOAuth2ServiceFromOAuthConfig(userService, stateRepo, config)
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

// createProfileHandler creates the profile endpoint handler
func createProfileHandler(userService Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get user from context (set by auth middleware)
		user, ok := GetUserFromContext(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "Not authenticated", nil)
			return
		}

		// Return user profile including API key
		response := map[string]interface{}{
			"username":    user.Email,
			"email":       user.Email,
			"name":        fmt.Sprintf("%s %s", user.GivenName, user.FamilyName),
			"given_name":  user.GivenName,
			"family_name": user.FamilyName,
			"picture":     user.Picture,
			"api_key":     user.APIKey,
		}

		writeJSON(w, http.StatusOK, response)
	}
}
