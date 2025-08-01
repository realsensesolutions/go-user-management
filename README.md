# go-user-management

A comprehensive user management package for Go applications, providing authentication middleware, user CRUD operations, API key management, and database migrations. Designed for RealSense Solutions projects but generic enough for any Go application.

## 🚀 Features

- **🔐 Complete Authentication System**: JWT + API key middleware with context helpers
- **👥 User Management**: Create, read, update, and delete users with role-based access
- **🔑 API Key Authentication**: Generate, validate, and manage API keys
- **🗄️ Database Migrations**: Embedded SQL migrations with auto-migration support
- **🛡️ HTTP Routes & Middleware**: Ready-to-use Chi router integration
- **🧪 Testing Support**: Full test coverage with mock implementations
- **📦 Multiple Backends**: Repository pattern for different storage backends
- **⚡ Production Ready**: Used in production RealSense applications

## 📦 Installation

```bash
go get github.com/realsensesolutions/go-user-management@latest
```

## 🚀 Getting Started

### 1. Basic Setup

First, set up your database and create the user service:

```go
package main

import (
    "database/sql"
    "log"
    
    user "github.com/realsensesolutions/go-user-management"
    "github.com/realsensesolutions/go-user-management/internal/sqlite"
    _ "modernc.org/sqlite"
)

func main() {
    // Open database connection
    db, err := sql.Open("sqlite", "users.db")
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    // Create repository and service
    repo := sqlite.NewRepository(db)
    service := user.NewService(repo)
    
    // Run migrations (development mode)
    migrator := user.NewMigrator(db)
    if err := migrator.AutoMigrate(); err != nil {
        log.Fatal("Migration failed:", err)
    }
    
    log.Println("User management system ready!")
}
```

### 2. Database Migrations

The package includes embedded SQL migrations that automatically create the required database schema:

```go
// Auto-migrate (recommended for development)
migrator := user.NewMigrator(db)
if err := migrator.AutoMigrate(); err != nil {
    log.Fatal("Migration failed:", err)
}

// Check migration status
status, err := migrator.GetMigrationStatus()
if err != nil {
    log.Fatal("Failed to get migration status:", err)
}
fmt.Printf("Applied migrations: %v\n", status.AppliedMigrations)

// Validate schema (ensures database matches expected structure)
if err := migrator.ValidateSchema(); err != nil {
    log.Fatal("Schema validation failed:", err)
}
```

### 3. Authentication Middleware

Set up HTTP middleware for JWT and API key authentication:

```go
package main

import (
    "context"
    "net/http"
    
    user "github.com/realsensesolutions/go-user-management"
    "github.com/go-chi/chi/v5"
)

func main() {
    r := chi.NewRouter()
    
    // Create auth config with JWT validator
    authConfig := user.DefaultAuthConfig(userService)
    authConfig.OIDCValidator = func(ctx context.Context, tokenString string) (*user.Claims, error) {
        // Your JWT validation logic here
        // This should validate the token and return user claims
        return validateJWTToken(ctx, tokenString)
    }
    
    // Apply authentication middleware
    r.Use(user.RequireAuthMiddleware(authConfig))
    
    // Protected routes
    r.Get("/profile", func(w http.ResponseWriter, r *http.Request) {
        user, ok := user.GetUserFromContext(r)
        if !ok {
            http.Error(w, "User not found", http.StatusUnauthorized)
            return
        }
        
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(user)
    })
    
    http.ListenAndServe(":8080", r)
}
```

## 🎯 Sentipulse Integration Example

Here's how Sentipulse backend integrates this package:

### main.go Integration

```go
package main

import (
    "context"
    "database/sql"
    "log"
    "net/http"
    
    "lambda-go-example/auth"
    user "github.com/realsensesolutions/go-user-management"
    "github.com/realsensesolutions/go-user-management/internal/sqlite"
    "github.com/go-chi/chi/v5"
)

func main() {
    // Database setup
    db, err := sql.Open("sqlite", "sentipulse.db")
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    // Create user service
    userRepo := sqlite.NewRepository(db)
    userService := user.NewService(userRepo)

    // Run migrations in development
    migrator := user.NewMigrator(db)
    if err := migrator.AutoMigrate(); err != nil {
        log.Fatal("Migration failed:", err)
    }

    // Setup router
    r := chi.NewRouter()

    // OIDC adapter that auto-creates users from JWT tokens
    oidcAdapter := func(ctx context.Context, tokenString string) (*user.Claims, error) {
        // Validate OIDC token using Sentipulse auth package
        oidcClaims, err := auth.ValidateOIDCToken(ctx, tokenString)
        if err != nil {
            return nil, err
        }

        // Check if user exists, create if not
        existingUser, err := userService.GetUserByEmail(ctx, oidcClaims.Email)
        if err != nil && err != user.ErrUserNotFound {
            return nil, err
        }

        if existingUser == nil {
            // Auto-create user from OIDC claims
            createReq := user.CreateUserRequest{
                ID:         oidcClaims.Sub,
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

        // Convert to external package claims
        return &user.Claims{
            Sub:        existingUser.ID,
            Email:      existingUser.Email,
            GivenName:  existingUser.GivenName,
            FamilyName: existingUser.FamilyName,
            Picture:    existingUser.Picture,
            Username:   existingUser.Email,
            Role:       existingUser.Role,
            Provider:   "jwt",
        }, nil
    }

    // Setup authentication middleware
    authConfig := user.DefaultAuthConfig(userService)
    authConfig.OIDCValidator = oidcAdapter
    authConfig.CookieName = "jwt"
    authConfig.APIKeyHeader = "X-Api-Key"

    // Apply middleware to protected routes
    r.Group(func(r chi.Router) {
        r.Use(user.RequireAuthMiddleware(authConfig))
        
        // All your protected routes here
        r.Get("/api/boards", boardHandler.GetBoards)
        r.Post("/api/boards", boardHandler.CreateBoard)
        // ... more routes
    })

    log.Println("Sentipulse server starting on :8080")
    http.ListenAndServe(":8080", r)
}
```

### Handler Integration

```go
package handlers

import (
    "encoding/json"
    "net/http"
    
    user "github.com/realsensesolutions/go-user-management"
    "lambda-go-example/auth"
)

// Convert external package claims to local auth claims
func getUserClaimsFromContext(r *http.Request) (*auth.OIDCClaims, error) {
    // Get claims from external package context
    externalClaims, ok := user.GetClaimsFromContext(r)
    if !ok {
        return nil, fmt.Errorf("claims not found in context")
    }

    // Convert to local claims format
    localClaims := &auth.OIDCClaims{
        Sub:        externalClaims.Sub,
        Email:      externalClaims.Email,
        GivenName:  externalClaims.GivenName,
        FamilyName: externalClaims.FamilyName,
        Picture:    externalClaims.Picture,
        Username:   externalClaims.Username,
    }
    
    return localClaims, nil
}

func (h *BoardHandler) GetBoards(w http.ResponseWriter, r *http.Request) {
    // Get authenticated user
    user, ok := user.GetUserFromContext(r)
    if !ok {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    // Your business logic here
    boards, err := h.boardService.GetBoardsByUserID(r.Context(), user.ID)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(boards)
}
```

## Quick Start

```go
package main

import (
    "context"
    "database/sql"
    "log"

    user "github.com/realsensesolutions/go-user-management"
    "github.com/realsensesolutions/go-user-management/internal/sqlite"
    _ "modernc.org/sqlite"
)

func main() {
    // Open database connection
    db, err := sql.Open("sqlite", "users.db")
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    // Create repository and service
    repo := sqlite.NewRepository(db)
    service := user.NewService(repo)

    ctx := context.Background()

    // Create a new user
    newUser, err := service.CreateUser(ctx, user.CreateUserRequest{
        ID:         "user-123",
        Email:      "john.doe@example.com",
        GivenName:  "John",
        FamilyName: "Doe",
        Role:       "user",
    })
    if err != nil {
        log.Fatal(err)
    }

    // Generate API key
    apiKey, err := service.GenerateAPIKey(ctx, newUser.ID, newUser.Email)
    if err != nil {
        log.Fatal(err)
    }

    // Validate API key
    authenticatedUser, err := service.ValidateAPIKey(ctx, apiKey)
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Authenticated user: %s", authenticatedUser.Email)
}
```

## Core Types

### User

```go
type User struct {
    ID         string    `json:"id"`
    Email      string    `json:"email"`
    GivenName  string    `json:"givenName"`
    FamilyName string    `json:"familyName"`
    Picture    string    `json:"picture"`
    Role       string    `json:"role"`
    CreatedAt  time.Time `json:"createdAt"`
    UpdatedAt  time.Time `json:"updatedAt"`
}
```

### Service Interface

```go
type Service interface {
    GetUserByID(ctx context.Context, userID string) (*User, error)
    GetUserByEmail(ctx context.Context, email string) (*User, error)
    CreateUser(ctx context.Context, req CreateUserRequest) (*User, error)
    UpdateUser(ctx context.Context, req UpdateUserRequest) (*User, error)
    DeleteUser(ctx context.Context, userID string) error
    ValidateAPIKey(ctx context.Context, apiKey string) (*User, error)
    GenerateAPIKey(ctx context.Context, userID, email string) (string, error)
    GetAPIKey(ctx context.Context, userID string) (string, error)
    ListUsers(ctx context.Context, limit, offset int) ([]*User, error)
}
```

## Database Schema

For SQLite implementation, create a users table:

```sql
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    given_name TEXT,
    family_name TEXT,
    picture TEXT,
    role TEXT DEFAULT 'user',
    api_key TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

## Custom Repository Implementation

Implement the `Repository` interface for your preferred database:

```go
type Repository interface {
    GetUserByID(userID string) (*User, error)
    GetUserByEmail(email string) (*User, error)
    CreateUser(req CreateUserRequest) (*User, error)
    UpdateUser(req UpdateUserRequest) (*User, error)
    DeleteUser(userID string) error
    GetAPIKey(userID string) (string, error)
    UpsertAPIKey(userID, email, apiKey string) error
    GetUserByAPIKey(apiKey string) (*User, error)
    ListUsers(ctx context.Context, limit, offset int) ([]*User, error)
}
```

## Error Handling

The package provides standard errors:

```go
var (
    ErrUserNotFound      = errors.New("user not found")
    ErrInvalidAPIKey     = errors.New("invalid API key")
    ErrUserAlreadyExists = errors.New("user already exists")
)
```

## Testing

Run the test suite:

```bash
go test -v
```

The package includes comprehensive tests with mock implementations for easy testing of your applications.

## 🛠️ Advanced Usage

### API Key Management

Generate and manage API keys for programmatic access:

```go
// Generate API key for a user
apiKey, err := userService.GenerateAPIKey(ctx, userID, userEmail)
if err != nil {
    log.Fatal("Failed to generate API key:", err)
}

// Validate API key
user, err := userService.ValidateAPIKey(ctx, apiKey)
if err != nil {
    log.Fatal("Invalid API key:", err)
}

// Get existing API key for a user
existingKey, err := userService.GetAPIKey(ctx, userID)
if err != nil {
    log.Fatal("Failed to get API key:", err)
}
```

### Custom Error Handling

Customize authentication error responses:

```go
authConfig := user.DefaultAuthConfig(userService)
authConfig.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
    response := map[string]string{
        "error": "Authentication failed",
        "message": err.Error(),
    }
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusUnauthorized)
    json.NewEncoder(w).Encode(response)
}
```

### Multiple Authentication Methods

Configure different authentication for different routes:

```go
// JWT only for web routes
jwtConfig := user.DefaultAuthConfig(userService)
jwtConfig.OIDCValidator = validateJWTToken
r.Group(func(r chi.Router) {
    r.Use(user.RequireAuthMiddleware(jwtConfig))
    r.Get("/web/profile", webHandler)
})

// API key only for API routes
apiConfig := user.DefaultAuthConfig(userService)
apiConfig.OIDCValidator = nil // Disable JWT
r.Group(func(r chi.Router) {
    r.Use(user.RequireAuthMiddleware(apiConfig))
    r.Get("/api/data", apiHandler)
})

// Optional auth for public routes with user context when available
optionalConfig := user.DefaultAuthConfig(userService)
optionalConfig.RequireAuth = false
r.Group(func(r chi.Router) {
    r.Use(user.RequireAuthMiddleware(optionalConfig))
    r.Get("/public/content", publicHandler)
})
```

## 🔧 Troubleshooting

### Common Issues

#### 1. Context Key Mismatch

**Problem**: "Claims not found in context" or "User not found in context"

**Solution**: Make sure you're using the external package's context helpers:

```go
// ❌ Wrong - using local context keys
claims, ok := r.Context().Value("claims").(*MyLocalClaims)

// ✅ Correct - using external package helpers
claims, ok := user.GetClaimsFromContext(r)
user, ok := user.GetUserFromContext(r)
```

#### 2. Database Migration Issues

**Problem**: "Table doesn't exist" or schema mismatch errors

**Solution**: Run migrations before using the service:

```go
migrator := user.NewMigrator(db)
if err := migrator.AutoMigrate(); err != nil {
    log.Fatal("Migration failed:", err)
}

// For production, check migration status first
status, err := migrator.GetMigrationStatus()
if err != nil {
    log.Fatal("Failed to get migration status:", err)
}
log.Printf("Applied migrations: %v", status.AppliedMigrations)
```

#### 3. Authentication Middleware Not Working

**Problem**: All requests return 401 Unauthorized

**Solution**: Ensure middleware is configured properly:

```go
// Make sure you have either JWT validator or API key header
authConfig := user.DefaultAuthConfig(userService)

// For JWT authentication
authConfig.OIDCValidator = yourJWTValidator

// For API key authentication (header: X-Api-Key)
// API key validation is automatic when validator is nil

// Apply middleware before your routes
r.Use(user.RequireAuthMiddleware(authConfig))
```

#### 4. User Auto-Creation Issues

**Problem**: JWT validation succeeds but user operations fail

**Solution**: Implement proper user auto-creation in your OIDC validator:

```go
oidcValidator := func(ctx context.Context, tokenString string) (*user.Claims, error) {
    // Validate token first
    oidcClaims, err := validateToken(tokenString)
    if err != nil {
        return nil, err
    }

    // Check if user exists, create if not
    existingUser, err := userService.GetUserByEmail(ctx, oidcClaims.Email)
    if err != nil && err != user.ErrUserNotFound {
        return nil, err
    }

    if existingUser == nil {
        // Auto-create user
        createReq := user.CreateUserRequest{
            ID:         oidcClaims.Sub,
            Email:      oidcClaims.Email,
            GivenName:  oidcClaims.GivenName,
            FamilyName: oidcClaims.FamilyName,
            Role:       "user",
        }
        existingUser, err = userService.CreateUser(ctx, createReq)
        if err != nil {
            return nil, err
        }
    }

    // Return claims
    return &user.Claims{
        Sub:   existingUser.ID,
        Email: existingUser.Email,
        // ... other fields
    }, nil
}
```

#### 5. Production Migration Issues

**Problem**: Need to control migrations in production

**Solution**: Use manual migration approach:

```go
// In production, don't auto-migrate
migrator := user.NewMigrator(db)

// Check what migrations need to be applied
status, err := migrator.GetMigrationStatus()
if err != nil {
    log.Fatal("Failed to get migration status:", err)
}

// Only proceed if you want to apply migrations
if len(status.PendingMigrations) > 0 {
    log.Printf("Pending migrations: %v", status.PendingMigrations)
    // Apply migrations manually or through deployment process
    if err := migrator.AutoMigrate(); err != nil {
        log.Fatal("Migration failed:", err)
    }
}
```

## Examples

See the repository for complete usage examples:

- **Basic Usage**: Simple user CRUD operations with SQLite
- **Authentication**: JWT and API key middleware integration  
- **Migrations**: Database schema management examples
- **Chi Router**: Complete web server with authentication

## Contributing

We welcome contributions! Please feel free to submit issues and pull requests.

## License

This package is part of the RealSense Solutions ecosystem and is available under standard open source terms.

## Security

This package handles user data and API keys. Ensure you:

- Use secure connections for database access
- Store API keys securely
- Validate all input data
- Follow security best practices for your specific use case

For security issues, please contact: security@realsensesolutions.com