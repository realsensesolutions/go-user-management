# go-user-management

A generic user management package for Go applications, providing clean interfaces for user CRUD operations, API key management, and authentication.

## Features

- **User Management**: Create, read, update, and delete users
- **API Key Authentication**: Generate and validate API keys for users
- **Generic Interfaces**: Repository pattern for different storage backends
- **SQLite Implementation**: Built-in SQLite repository implementation
- **Type Safety**: Comprehensive Go types and error handling
- **Testing**: Full test coverage with mock implementations

## Installation

```bash
go get github.com/realsensesolutions/go-user-management
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

## Examples

See the `examples/` directory for complete usage examples:

- `basic_usage.go` - Complete example with SQLite
- More examples coming soon

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