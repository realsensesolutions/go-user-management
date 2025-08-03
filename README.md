# go-user-management

A production-ready user management package for Go applications, providing authentication middleware, user CRUD operations, API key management, and database migrations.

## ✨ Core Features (Production-Used)

- **🔐 Authentication Middleware**: JWT + API key middleware with context helpers
- **👥 Essential User Operations**: Create, retrieve users with role-based access  
- **🔑 API Key Management**: Generate, validate, and manage API keys
- **🗄️ Database Migrations**: Embedded SQL migrations with auto-migration support
- **📦 Repository Pattern**: Clean separation with SQLite implementation

## 🚀 Quick Start

### Installation

```bash
go get github.com/realsensesolutions/go-user-management@latest
```

### Basic Setup (Production Pattern)

```go
package main

import (
    "context"
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
    
    // 2. Create user service
    userService := createUserService()
    
    // 3. Setup authentication middleware
    setupAuthMiddleware(userService)
}

// Create user service using the production pattern
func createUserService() user.Service {
    repo := user.NewSQLiteRepository(database.GetDB)
    return user.NewService(repo)
}
```

### Authentication Middleware Setup

```go
func setupAuthMiddleware(userService user.Service) *chi.Mux {
    r := chi.NewRouter()
    
    // Configure authentication
    authConfig := user.DefaultAuthConfig(userService)
    authConfig.OIDCValidator = validateOIDCTokenWithUserCreation
    
    // Protected routes
    r.Group(func(r chi.Router) {
        // Apply authentication middleware
        r.Use(user.RequireAuthMiddleware(authConfig))
        
        // Your protected routes here...
        r.Get("/profile", getProfileHandler)
    })
    
    return r
}
```

### OIDC Integration with Auto-User Creation

```go
func validateOIDCTokenWithUserCreation(ctx context.Context, tokenString string) (*user.Claims, error) {
    // 1. Validate OIDC token using your auth system
    oidcClaims, err := auth.ValidateOIDCToken(ctx, tokenString)
    if err != nil {
        return nil, err
    }
    
    // 2. Check if user exists, create if not
    existingUser, err := userService.GetUserByEmail(ctx, oidcClaims.Email)
    if err != nil && err != user.ErrUserNotFound {
        return nil, err
    }
    
    if existingUser == nil {
        // Auto-create user from OIDC claims
        createReq := user.CreateUserRequest{
            ID:         oidcClaims.Email,
            Email:      oidcClaims.Email,
            GivenName:  oidcClaims.GivenName,
            FamilyName: oidcClaims.FamilyName,
            Picture:    oidcClaims.Picture,
            Role:       "user",
        }
        existingUser, err = userService.CreateUser(ctx, createReq)
        if err != nil {
            return nil, err
        }
    }
    
    // 3. Return standardized claims
    return &user.Claims{
        Sub:        existingUser.ID,
        Email:      existingUser.Email,
        GivenName:  existingUser.GivenName,
        FamilyName: existingUser.FamilyName,
        Picture:    existingUser.Picture,
        APIKey:     existingUser.APIKey,
        Role:       existingUser.Role,
        Provider:   "oidc",
    }, nil
}
```

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
// Middleware
func RequireAuthMiddleware(config *AuthConfig) func(http.Handler) http.Handler
func DefaultAuthConfig(service Service) *AuthConfig

// Context helpers
func GetUserFromContext(r *http.Request) (*User, bool)
func GetClaimsFromContext(r *http.Request) (*Claims, bool)  
func GetUserIDFromContext(r *http.Request) (string, bool)

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
```

## 🌟 Advanced Features

### HTTP Routes (Optional)

The package includes optional HTTP route handlers for complete user management:

```go
import "github.com/realsensesolutions/go-user-management"

// Setup optional HTTP routes
config := &user.RouteConfig{
    Service: userService,
    RequireAuth: true,
}
user.SetupUserRoutes(router, config)
```

**Note**: Most applications use the core service and middleware directly rather than the pre-built HTTP routes.

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

## 🤝 Production Usage

This package is used in production at RealSense Solutions and handles:
- Authentication for thousands of users
- API key management for service-to-service communication  
- OIDC token validation with auto-user provisioning
- Role-based access control

## 📄 License

MIT License