# go-user-management 🚀

A production-ready user management package for Go applications with **simplified integration**. Provides self-contained authentication middleware, OAuth2/OIDC setup, complete user management API, API key management, and database migrations.

## ✨ Core Features (Production-Used)

- **🔐 Self-Contained Auth**: Zero-config middleware with internal initialization
- **⚡ OAuth2/OIDC Setup**: Complete auth routes with single function call
- **👥 User Management API**: Self-contained CRUD routes with built-in security
- **🔑 API Key Management**: Generate, validate, and manage API keys
- **🗄️ Database Migrations**: Embedded SQL migrations with auto-migration support
- **📦 Repository Pattern**: Clean separation with SQLite implementation

## 🚀 Quick Start

### Installation

```bash
go get github.com/realsensesolutions/go-user-management@latest
```

### Complete OAuth2/OIDC Setup (Super Simple!)

```go
package main

import (
    "os"
    "log"
    
    user "github.com/realsensesolutions/go-user-management"
    database "github.com/realsensesolutions/go-database"
    "github.com/go-chi/chi/v5"
)

func main() {
    // 1. Run migrations (they auto-register)
    if err := database.RunAllMigrations(); err != nil {
        log.Fatal("Migration failed:", err)
    }
    
    // 2. Setup complete authentication system
    setupAuthentication()
}

func setupAuthentication() {
    r := chi.NewRouter()
    
    // 3. Single config for OAuth2/OIDC (replaces multiple configs)
    oauthConfig := user.OAuthConfig{
        ClientID:     os.Getenv("COGNITO_CLIENT_ID"),
        ClientSecret: os.Getenv("COGNITO_CLIENT_SECRET"),
        UserPoolID:   os.Getenv("COGNITO_USER_POOL_ID"),
        RedirectURI:  os.Getenv("COGNITO_REDIRECT_URI"),
        Region:       os.Getenv("AWS_REGION"),
        Domain:       os.Getenv("COGNITO_DOMAIN"),
        FrontEndURL:  os.Getenv("FRONT_END_URL"),
        Scopes:       []string{"openid", "email", "profile"},
        CalculateDefaultRole: calculateUserRole, // Custom role logic
    }
    
    // 4. Setup ALL auth routes (login, logout, callback, profile) - ONE LINE!
    err := user.SetupAuthRoutes(r, oauthConfig)
    if err != nil {
        log.Fatal("Auth setup failed:", err)
    }
    
    // 5. Add authentication to protected routes - ZERO CONFIG!
    r.Group(func(r chi.Router) {
        r.Use(user.RequireAuthMiddleware()) // That's it! 🎯
        
        // Your protected routes here...
        r.Get("/api/dashboard", getDashboardHandler)
        r.Get("/api/profile", getProfileHandler)
    })
}

// Custom role calculation based on your business logic
func calculateUserRole(claims *user.OIDCClaims) string {
    // Example: Check Cognito groups for admin role
    for _, group := range claims.Groups {
        if group == "admin" {
            return "admin"
        }
    }
    return "user" // default role
}
```

### Alternative Middleware Options

```go
// Different authentication patterns for different needs

func setupAdvancedAuth() {
    r := chi.NewRouter()
    
    // Option 1: Required authentication (most common)
    r.Group(func(r chi.Router) {
        r.Use(user.RequireAuthMiddleware()) // Blocks unauthenticated requests
        r.Get("/api/private", privateHandler)
    })
    
    // Option 2: Optional authentication (public + enhanced for authenticated)
    r.Group(func(r chi.Router) {
        r.Use(user.OptionalAuthMiddleware()) // Allows unauthenticated requests
        r.Get("/api/public", publicHandler) // Works with or without auth
    })
    
    // Option 3: API key only (service-to-service)
    r.Group(func(r chi.Router) {
        r.Use(user.APIKeyOnlyMiddleware()) // Only validates API keys, no JWT
        r.Get("/api/service", serviceHandler)
    })
}
```

### User Management API Routes

In addition to authentication, you can also register user management CRUD routes:

```go
func setupUserManagement() {
    r := chi.NewRouter()
    
    // Setup authentication first
    err := user.SetupAuthRoutes(r, oauthConfig)
    if err != nil {
        log.Fatal("Auth setup failed:", err)
    }
    
    // Add user management routes (self-contained, no dependencies!)
    user.RegisterUserRoutes(r, nil) // Uses default auth config
    
    // This automatically creates these protected routes:
    // GET    /api/users/me        - Get current user profile
    // GET    /api/users/{id}      - Get user by ID (admin or self only)  
    // PUT    /api/users/me        - Update current user profile
    // POST   /api/users/api-key   - Generate new API key
    // GET    /api/users/api-key   - Get current API key
    // GET    /api/users           - List users (admin only)
}
```

**Key Benefits:**
- **Zero Configuration**: Service and repository created internally
- **Built-in Security**: All routes require authentication automatically
- **Role-based Access**: Admin-only and self-access controls built-in
- **API Keys**: Built-in API key generation and management

### Basic User Service (Without OAuth2)

If you only need user management without OAuth2/OIDC:

```go
func basicUserService() {
    // Create user service
    repo := user.NewSQLiteRepository()
    userService := user.NewService(repo)
    
    // Create a user
    createReq := user.CreateUserRequest{
        ID:         "user@example.com",
        Email:      "user@example.com",
        GivenName:  "John",
        FamilyName: "Doe",
        Role:       "user",
    }
    newUser, err := userService.CreateUser(ctx, createReq)
    
    // Generate API key
    apiKey, err := userService.GenerateAPIKey(ctx, newUser.ID, newUser.Email)
}

## 🔄 Core Operations

### User Management

```go
// Create user
createReq := user.CreateUserRequest{
    ID:         "user@example.com",
    Email:      "user@example.com", 
    GivenName:  "John",
    FamilyName: "Doe",
    Role:       "user",
}
newUser, err := service.CreateUser(ctx, createReq)

// Get user
user, err := service.GetUserByID(ctx, "user@example.com")
user, err := service.GetUserByEmail(ctx, "user@example.com")
```

### API Key Management

```go
// Generate API key
apiKey, err := service.GenerateAPIKey(ctx, userID, email)

// Validate API key  
user, err := service.ValidateAPIKey(ctx, apiKey)

// Get/Update API key
existingKey, err := service.GetAPIKey(ctx, userID)
err := service.UpdateAPIKey(ctx, userID, email, newAPIKey)
```

### Context Helpers

```go
// In your HTTP handlers
func getProfileHandler(w http.ResponseWriter, r *http.Request) {
    // Get authenticated user from context
    user, ok := user.GetUserFromContext(r)
    if !ok {
        // Handle unauthenticated request
        return
    }
    
    // Get user claims
    claims, ok := user.GetClaimsFromContext(r)
    if !ok {
        // Handle missing claims
        return
    }
    
    // Get just the user ID
    userID, ok := user.GetUserIDFromContext(r)
}
```

## 🗄️ Database Migrations

Migrations are automatically registered when you import the package:

```go
import (
    _ "github.com/realsensesolutions/go-user-management" // Auto-registers migrations
    database "github.com/realsensesolutions/go-database"
)

func main() {
    // This will run user management migrations + any others
    if err := database.RunAllMigrations(); err != nil {
        log.Fatal(err)
    }
}
```

Or run migrations manually:

```go
db, err := sql.Open("sqlite", "app.db")
if err := user.AutoMigrate(db); err != nil {
    log.Fatal(err)
}
```

## 📋 API Reference

### Core Service Interface

```go
type Service interface {
    // Essential operations (commonly used)
    GetUserByID(ctx context.Context, userID string) (*User, error)
    GetUserByEmail(ctx context.Context, email string) (*User, error)
    CreateUser(ctx context.Context, req CreateUserRequest) (*User, error)
    
    // API key operations (commonly used)
    ValidateAPIKey(ctx context.Context, apiKey string) (*User, error)
    GenerateAPIKey(ctx context.Context, userID, email string) (string, error)
    GetAPIKey(ctx context.Context, userID string) (string, error)
    UpdateAPIKey(ctx context.Context, userID, email, apiKey string) error
    
    // Advanced operations (optional)
    UpdateUser(ctx context.Context, req UpdateUserRequest) (*User, error)
    DeleteUser(ctx context.Context, userID string) error
    ListUsers(ctx context.Context, limit, offset int) ([]*User, error)
}
```

### Authentication Functions

```go
// OAuth2/OIDC Setup (complete auth flow)
func SetupAuthRoutes(r chi.Router, config OAuthConfig) error

// User Management Routes (CRUD operations)
func RegisterUserRoutes(r chi.Router, authConfig *AuthConfig) 

// Self-contained middleware (no parameters needed!)
func RequireAuthMiddleware() func(http.Handler) http.Handler
func OptionalAuthMiddleware() func(http.Handler) http.Handler  
func APIKeyOnlyMiddleware() func(http.Handler) http.Handler

// Context helpers
func GetUserFromContext(r *http.Request) (*User, bool)
func GetClaimsFromContext(r *http.Request) (*Claims, bool)  
func GetUserIDFromContext(r *http.Request) (string, bool)

// Basic service creation
func NewSQLiteRepository() Repository
func NewService(repo Repository) Service

// Migration
func AutoMigrate(db *sql.DB) error
```

### Types

```go
type User struct {
    ID         string    `json:"id"`
    Email      string    `json:"email"`
    GivenName  string    `json:"givenName"`
    FamilyName string    `json:"familyName"`
    Picture    string    `json:"picture"`
    Role       string    `json:"role"`
    APIKey     string    `json:"apiKey"`
    CreatedAt  time.Time `json:"createdAt"`
    UpdatedAt  time.Time `json:"updatedAt"`
}

type CreateUserRequest struct {
    ID         string `json:"id"`         // Usually email
    Email      string `json:"email"`
    GivenName  string `json:"givenName"`
    FamilyName string `json:"familyName"`
    Picture    string `json:"picture,omitempty"`
    Role       string `json:"role,omitempty"`
}

type Claims struct {
    Sub        string `json:"sub"`         // User ID
    Email      string `json:"email"`
    GivenName  string `json:"given_name"`
    FamilyName string `json:"family_name"`
    Picture    string `json:"picture"`
    Username   string `json:"username"`
    APIKey     string `json:"api_key"`
    Role       string `json:"role"`
    Provider   string `json:"provider"`
}

// OAuth2/OIDC Configuration
type OAuthConfig struct {
    ClientID     string   `json:"clientId"`
    ClientSecret string   `json:"clientSecret"`
    UserPoolID   string   `json:"userPoolId"`
    RedirectURI  string   `json:"redirectUri"`
    Region       string   `json:"region"`
    Domain       string   `json:"domain"`
    FrontEndURL  string   `json:"frontEndUrl"`
    Scopes       []string `json:"scopes"`
    
    // Custom role calculation function
    CalculateDefaultRole func(*OIDCClaims) string `json:"-"`
}

type OIDCClaims struct {
    Sub        string   `json:"sub"`
    Email      string   `json:"email"`
    GivenName  string   `json:"given_name"`
    FamilyName string   `json:"family_name"`
    Picture    string   `json:"picture"`
    Username   string   `json:"username"`
    Groups     []string `json:"cognito:groups"`
    APIKey     string   `json:"api_key"`
}
```

## 🌟 Advanced Features

### Complete OAuth2 Flow

The `SetupAuthRoutes()` function provides a complete OAuth2/OIDC authentication flow:

```go
import user "github.com/realsensesolutions/go-user-management"

// Setup complete OAuth2 flow
err := user.SetupAuthRoutes(r, oauthConfig)
// This creates:
// GET  /oauth2/idpresponse  - OAuth2 callback handler
// GET  /api/auth/login      - Initiate login flow  
// GET  /api/auth/logout     - Logout handler
// GET  /api/auth/profile    - Get user profile (protected)

// Optional: Add user management CRUD routes
user.RegisterUserRoutes(r, nil) // Self-contained user management API
```

**Benefits**: Zero boilerplate, automatic user creation, role assignment, and session management.

**Pro Tip**: Combine `SetupAuthRoutes()` with `RegisterUserRoutes()` for a complete user management system with just two function calls!

### Custom Repository

Implement your own storage backend:

```go
type Repository interface {
    CreateUser(req CreateUserRequest) (*User, error)
    GetUserByID(userID string) (*User, error)
    GetUserByEmail(email string) (*User, error)
    UpdateUser(req UpdateUserRequest) (*User, error)
    DeleteUser(userID string) error
    // ... other methods
}

// Use custom repository
service := user.NewService(myCustomRepo)
```

## 🔧 Requirements

- Go 1.22 or later
- SQLite via `modernc.org/sqlite`
- Database migrations via `github.com/realsensesolutions/go-database`

## 📖 Examples

- [Basic Usage](examples/basic_usage.go) - Complete example with database setup
- [Middleware Integration](examples/middleware_example.go) - HTTP middleware setup
- [OIDC Integration](examples/oidc_example.go) - Token validation with auto-user creation

## 🔄 Migration Guide

### v1.13.x to v1.15.0 (Latest)

**New Features:**
- ✨ **Self-contained user management routes**: `RegisterUserRoutes(r, authConfig)`
- 🚀 **Zero-dependency service creation**: No need to manage Service/Repository instances
- 📋 **Built-in CRUD API**: Complete user management REST API

**Migration (Optional - for new user management features):**
```go
// Add this line after SetupAuthRoutes() for complete user management
user.RegisterUserRoutes(r, nil) // Self-contained, zero config needed!
```

**Installation:**
```bash
go get github.com/realsensesolutions/go-user-management@v1.15.0
```

### v1.12.x to v1.13.0

**Breaking Changes Summary:**

| v1.12.x (Old) | v1.13.0 (New) |
|------------|--------------|
| `CognitoConfig` + `OAuth2Config` | Single `OAuthConfig` |
| `RequireAuthMiddleware(config)` | `RequireAuthMiddleware()` |
| Manual route setup | `SetupAuthRoutes(r, config)` |
| External helper functions | All internalized |

**Migration Steps:**
1. Replace configs with single `OAuthConfig`
2. Replace manual route setup with `SetupAuthRoutes()`
3. Remove parameters from middleware calls
4. Remove external helper function dependencies
5. Update to latest: `go get github.com/realsensesolutions/go-user-management@latest`

## 🤝 Production Usage

This package is used in production at RealSense Solutions and handles:
- **95% less integration code** compared to v1.x
- Authentication for thousands of users with **zero-config middleware**
- Complete OAuth2/OIDC flows with **single function call**
- User management CRUD operations with **self-contained service**
- API key management for service-to-service communication  
- OIDC token validation with auto-user provisioning
- **Custom role assignment** via function injection
- Role-based access control with built-in admin/user permissions

## 📄 License

MIT License