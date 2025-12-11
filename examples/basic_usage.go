package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"

	"github.com/go-chi/chi/v5"
	user "github.com/realsensesolutions/go-user-management"
)

func main() {
	// This example demonstrates JWT/Cognito-based authentication and user management
	// All user data is stored in AWS Cognito (no database needed)

	// Configure OAuth settings (normally from environment variables)
	oauthConfig := &user.OAuthConfig{
		ClientID:     "your-cognito-client-id",
		ClientSecret: "your-cognito-client-secret",
		UserPoolID:   "us-east-1_XXXXXXXXX",
		RedirectURI:  "http://localhost:8000/oauth2/idpresponse",
		Region:       "us-east-1",
		Domain:       "your-cognito-domain",
		FrontEndURL:  "http://localhost:3000",
		Scopes:       []string{"openid", "email", "profile"},
		CalculateDefaultRole: func(claims *user.OIDCClaims) string {
			// Custom role calculation logic
			for _, group := range claims.Groups {
				if group == "admin" {
					return "admin"
				}
			}
			return "user"
		},
	}

	// Set global OAuth config (required for all operations)
	user.SetOAuthConfig(oauthConfig)

	// Create router using chi (required by SetupAuthRoutes)
	router := chi.NewRouter()

	// Setup authentication routes (OAuth login, callback, logout, profile)
	if err := user.SetupAuthRoutes(router); err != nil {
		log.Fatal("Failed to setup auth routes:", err)
	}

	// Example: Protected route using authentication middleware
	protectedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := user.GetClaimsFromContext(r)
		if !ok {
			http.Error(w, "Not authenticated", http.StatusUnauthorized)
			return
		}

		fmt.Fprintf(w, "Hello, %s! Your email is %s and role is %s\n",
			claims.Username, claims.Email, claims.Role)
	})

	// Example: User management operations
	userManagementHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Get current user from context
		currentUser, ok := user.GetUserFromContext(r)
		if !ok {
			http.Error(w, "Not authenticated", http.StatusUnauthorized)
			return
		}

		// Example: Get user by email
		userProfile, err := user.GetUser(ctx, currentUser.Email)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to get user: %v", err), http.StatusInternalServerError)
			return
		}

		// Example: Update user profile
		updated, err := user.UpdateProfile(ctx, currentUser.Email, user.ProfileUpdate{
			GivenName:  stringPtr("Updated"),
			FamilyName: stringPtr("Name"),
		})
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to update profile: %v", err), http.StatusInternalServerError)
			return
		}

		// Example: Generate API key
		apiKey, err := user.GenerateAPIKey(ctx, currentUser.Email)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to generate API key: %v", err), http.StatusInternalServerError)
			return
		}

		fmt.Fprintf(w, "User: %+v\nUpdated: %+v\nAPI Key: %s\n",
			userProfile, updated, apiKey)
	})

	// Example: Admin operations (list users)
	adminHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Check if user is admin (you'd add your own admin check here)
		currentUser, ok := user.GetUserFromContext(r)
		if !ok || currentUser.Role != "admin" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// List users with pagination
		users, err := user.ListUsers(ctx, 20, 0)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to list users: %v", err), http.StatusInternalServerError)
			return
		}

		fmt.Fprintf(w, "Found %d users:\n", len(users))
		for _, u := range users {
			fmt.Fprintf(w, "  - %s (%s %s) - Role: %s\n",
				u.Email, u.GivenName, u.FamilyName, u.Role)
		}
	})

	// Apply authentication middleware
	router.Group(func(r chi.Router) {
		r.Use(user.RequireAuthMiddleware())
		r.Handle("/protected", protectedHandler)
		r.Handle("/api/user-management", userManagementHandler)
		r.Handle("/api/admin/users", adminHandler)
	})

	// Test the setup
	fmt.Println("✅ Authentication routes configured")
	fmt.Println("Available routes:")
	fmt.Println("  GET  /api/auth/login      - Initiate OAuth login")
	fmt.Println("  GET  /oauth2/idpresponse - OAuth callback")
	fmt.Println("  GET  /api/auth/logout    - Logout")
	fmt.Println("  GET  /api/auth/profile   - Get user profile (protected)")
	fmt.Println("  GET  /protected         - Example protected route")
	fmt.Println("  GET  /api/user-management - User management operations")
	fmt.Println("  GET  /api/admin/users    - List users (admin only)")

	// Start server (in real app, use http.ListenAndServe)
	server := httptest.NewServer(router)
	defer server.Close()

	fmt.Printf("\n✅ Server started at %s\n", server.URL)
	fmt.Println("\nNote: This is a test server. In production, use http.ListenAndServe()")
	fmt.Println("\nUser Management API Examples:")
	fmt.Println("  - GetUser(ctx, email)")
	fmt.Println("  - CreateUser(ctx, CreateUserRequest{...})")
	fmt.Println("  - UpdateProfile(ctx, email, ProfileUpdate{...})")
	fmt.Println("  - UpdateRole(ctx, email, role)")
	fmt.Println("  - GenerateAPIKey(ctx, email)")
	fmt.Println("  - ValidateAPIKey(ctx, apiKey)")
	fmt.Println("  - ListUsers(ctx, limit, offset)")
	fmt.Println("  - DeleteUser(ctx, email)")
}

func stringPtr(s string) *string {
	return &s
}
