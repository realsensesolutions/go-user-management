# go-user-management 🚀

A production-ready user management package for Go applications with **Cognito-backed persistence**. Provides self-contained authentication middleware, OAuth2/OIDC setup, and a clean user management API that abstracts away AWS Cognito complexity.

## ✨ Core Features

- **🔐 Self-Contained Auth**: Zero-config middleware with internal initialization
- **⚡ OAuth2/OIDC Setup**: Complete auth routes with single function call
- **👥 User Management API**: Clean, domain-focused API functions (Cognito-backed)
- **🔑 API Key Management**: Generate, validate, and manage API keys
- **🌐 Cognito Integration**: AWS Cognito as persistence layer (hidden implementation detail)
- **📦 Stateless OAuth State**: Encrypted, stateless OAuth state management (serverless-ready)

## 🚀 Quick Start

### Installation

```bash
go get github.com/realsensesolutions/go-user-management@latest
```

### Complete OAuth2/OIDC Setup

```go
package main

import (
    "os"
    "log"
    
    user "github.com/realsensesolutions/go-user-management"
    "github.com/go-chi/chi/v5"
)

func main() {
    // 1. Setup complete authentication system
    setupAuthentication()
}

func setupAuthentication() {
    r := chi.NewRouter()
    
    // 2. Single config for OAuth2/OIDC
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
    
    // 3. Set OAuth config globally
    user.SetOAuthConfig(&oauthConfig)
    
    // 4. Setup ALL auth routes (login, logout, callback, profile) - ONE LINE!
    err := user.SetupAuthRoutes(r)
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

### User Management API

The package provides a clean, domain-focused API for user operations. All functions use Cognito as the persistence layer, but Cognito complexity is hidden:

**Note:** Use `CreateUser()` for OAuth flows where Cognito handles user creation automatically. Use `CreateUserWithInvitation()` for admin-initiated invitations that require temporary passwords.

```go
import (
    "context"
    user "github.com/realsensesolutions/go-user-management"
)

func userManagementExample(ctx context.Context) {
    // Set OAuth config first (required for all operations)
    user.SetOAuthConfig(&oauthConfig)
    
    // Get user by email
    user, err := user.GetUser(ctx, "john@example.com")
    if err != nil {
        if err == user.ErrUserNotFound {
            // Handle not found
        }
        return
    }
    
    // Create a new user (for OAuth flows - no password set)
    newUser, err := user.CreateUser(ctx, user.CreateUserRequest{
        Email:      "newuser@example.com",
        GivenName:  "New",
        FamilyName: "User",
        Role:       "user",
    })
    
    // Create user with invitation (for admin invitations - sets temporary password)
    invitedUser, tempPassword, err := user.CreateUserWithInvitation(ctx, user.CreateUserRequest{
        Email:      "invited@example.com",
        GivenName:  "Invited",
        FamilyName: "User",
        Role:       "user",
    })
    // tempPassword can be sent via email - user must change on first login
    
    // Update user profile
    updated, err := user.UpdateProfile(ctx, "john@example.com", user.ProfileUpdate{
        GivenName:  stringPtr("John"),
        FamilyName: stringPtr("Smith"),
        Picture:    stringPtr("https://example.com/avatar.jpg"),
    })
    
    // Update user role
    _, err = user.UpdateRole(ctx, "john@example.com", "FieldOfficer")
    
    // Generate API key
    apiKey, err := user.GenerateAPIKey(ctx, "john@example.com")
    
    // Validate API key
    user, err := user.ValidateAPIKey(ctx, apiKey)
    
    // List users (with pagination)
    users, err := user.ListUsers(ctx, 20, 0)
    
    // Delete user
    err = user.DeleteUser(ctx, "john@example.com")
}

func stringPtr(s string) *string {
    return &s
}
```

### Authentication Middleware

```go
func setupRoutes() {
    r := chi.NewRouter()
    
    // Required authentication (most common)
    r.Group(func(r chi.Router) {
        r.Use(user.RequireAuthMiddleware()) // Blocks unauthenticated requests
        r.Get("/api/private", privateHandler)
    })
}
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
    
    // Get just the user email (used as ID)
    userID, ok := user.GetUserIDFromContext(r)
}
```

## 📋 API Reference

### User Management Functions

```go
// User CRUD Operations
func GetUser(ctx context.Context, email string) (*User, error)
func CreateUser(ctx context.Context, req CreateUserRequest) (*User, error)
func CreateUserWithInvitation(ctx context.Context, req CreateUserRequest) (*User, string, error)
func UpdateProfile(ctx context.Context, email string, update ProfileUpdate) (*User, error)
func UpdateRole(ctx context.Context, email string, role string) (*User, error)
func DeleteUser(ctx context.Context, email string) error
func ListUsers(ctx context.Context, limit, offset int) ([]*User, error)

// API Key Management
func GenerateAPIKey(ctx context.Context, email string) (string, error)
func GetAPIKey(ctx context.Context, email string) (string, error)
func RotateAPIKey(ctx context.Context, email string) (string, error)
func ValidateAPIKey(ctx context.Context, apiKey string) (*User, error)

// Token Lookup (for auth middleware)
func FindUserByToken(ctx context.Context, token string) (*Claims, error)
```

### Authentication Functions

```go
// OAuth2/OIDC Setup (complete auth flow)
func SetupAuthRoutes(r chi.Router) error

// OAuth Configuration (programmatic setup)
func SetOAuthConfig(config *OAuthConfig)
func GetOAuthConfig() *OAuthConfig

// Self-contained middleware (no parameters needed!)
func RequireAuthMiddleware() func(http.Handler) http.Handler

// Context helpers
func GetUserFromContext(r *http.Request) (*User, bool)
func GetClaimsFromContext(r *http.Request) (*Claims, bool)  
func GetUserIDFromContext(r *http.Request) (string, bool)
```

### Types

```go
// User represents a user in the system (Cognito-backed, but Cognito-agnostic)
type User struct {
    Email      string `json:"email"`       // Primary identifier
    GivenName  string `json:"givenName"`
    FamilyName string `json:"familyName"`
    Picture    string `json:"picture"`
    Role       string `json:"role"`
    APIKey     string `json:"apiKey,omitempty"` // Omitted if not set
}

// CreateUserRequest represents a request to create a new user
type CreateUserRequest struct {
    Email      string `json:"email"`
    GivenName  string `json:"givenName"`
    FamilyName string `json:"familyName"`
    Picture    string `json:"picture,omitempty"`
    Role       string `json:"role,omitempty"`
}

// ProfileUpdate represents fields that can be updated in a user profile
type ProfileUpdate struct {
    GivenName  *string `json:"givenName,omitempty"`
    FamilyName *string `json:"familyName,omitempty"`
    Picture    *string `json:"picture,omitempty"`
}

// Claims represents authentication claims (used by middleware)
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

### Error Types

```go
var (
    ErrUserNotFound      = errors.New("user not found")
    ErrUserAlreadyExists = errors.New("user already exists")
    ErrInvalidInput      = errors.New("invalid input")
    ErrInvalidAPIKey     = errors.New("invalid API key")
    ErrPermissionDenied  = errors.New("permission denied")
)
```

## 🌟 Advanced Features

### Complete OAuth2 Flow

The `SetupAuthRoutes()` function provides a complete OAuth2/OIDC authentication flow:

```go
import user "github.com/realsensesolutions/go-user-management"

// Set OAuth config globally first
user.SetOAuthConfig(&oauthConfig)

// Setup complete OAuth2 flow
err := user.SetupAuthRoutes(r)
// This creates:
// GET  /oauth2/idpresponse  - OAuth2 callback handler
// GET  /api/auth/login      - Initiate login flow  
// GET  /api/auth/logout     - Logout handler
// GET  /api/auth/profile    - Get user profile (protected)
```

**Benefits**: Zero boilerplate, automatic user creation, role assignment, and session management.

### Token-Based Authentication

The middleware supports both JWT tokens (from cookies) and opaque tokens (from Authorization headers):

```go
// JWT token in cookie (standard OAuth flow)
// Cookie: jwt=<jwt-token>

// Opaque token in Authorization header (API access)
// Authorization: Bearer <opaque-token>
```

The middleware automatically detects token type and validates accordingly.

### Stateless OAuth State Management

OAuth state is managed using AES-256-GCM symmetric encryption, making it stateless and serverless-ready. See [docs/state.md](docs/state.md) for details.

## 🔧 Requirements

- Go 1.22 or later
- AWS Cognito User Pool (for user persistence)
- AWS SDK for Go v2 (automatically included)

## 🔐 AWS Cognito Setup

### Required Cognito Custom Attributes

Your Cognito User Pool must have these custom attributes:

- `custom:role` - User role (e.g., "user", "admin", "FieldOfficer")
- `custom:apiKey` - API key for service-to-service authentication

### AWS Permissions

Your AWS credentials need these permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cognito-idp:AdminGetUser",
        "cognito-idp:AdminCreateUser",
        "cognito-idp:AdminUpdateUserAttributes",
        "cognito-idp:AdminDeleteUser",
        "cognito-idp:AdminListUsers",
        "cognito-idp:AdminSetUserPassword"
      ],
      "Resource": "arn:aws:cognito-idp:REGION:ACCOUNT:userpool/USER_POOL_ID"
    }
  ]
}
```

## 📖 Examples

- [Basic Usage](examples/basic_usage.go) - Complete example with OAuth setup
- See examples directory for more usage patterns

## 🔄 Migration Guide

### From SQLite/PostgreSQL to Cognito

**Breaking Changes:**

| Old (v1.x) | New (v2.x) |
|------------|------------|
| `Service` interface | Direct function calls (`GetUser()`, `CreateUser()`, etc.) |
| `Repository` interface | Removed (Cognito is implementation detail) |
| `User.ID` field | Use `User.Email` as identifier |
| `User.CreatedAt` / `UpdatedAt` | Removed (not available from Cognito) |
| `CreateUserRequest.ID` | Removed (email is primary identifier) |
| `UpdateUserRequest` | Replaced with `ProfileUpdate` |
| Database migrations | Removed (Cognito manages users) |

**Migration Steps:**

1. Remove database/SQLite dependencies
2. Set up AWS Cognito User Pool with custom attributes
3. Replace `Service` calls with direct API functions:
   ```go
   // Old
   service := user.NewService(repo)
   user, err := service.GetUserByEmail(ctx, email)
   
   // New
   user, err := user.GetUser(ctx, email)
   ```
4. Update `User` type usage (remove ID, CreatedAt, UpdatedAt fields)
5. Use `email` as user identifier instead of `ID`

## 🤝 Production Usage

This package is used in production at RealSense Solutions and handles:
- Authentication for thousands of users with **zero-config middleware**
- Complete OAuth2/OIDC flows with **single function call**
- User management operations backed by **AWS Cognito**
- API key management for service-to-service communication  
- OIDC token validation with auto-user provisioning
- **Custom role assignment** via function injection
- Role-based access control with built-in admin/user permissions
- **Serverless-ready** stateless OAuth state management

## 📄 License

MIT License
