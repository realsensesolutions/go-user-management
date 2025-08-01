package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	user "github.com/realsensesolutions/go-user-management"
	_ "modernc.org/sqlite"
)

func main() {
	// Open database connection
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		log.Fatal("Failed to open database:", err)
	}
	defer db.Close()

	// Create users table
	err = createUsersTable(db)
	if err != nil {
		log.Fatal("Failed to create users table:", err)
	}

	// Create repository and service
	repo := user.NewSQLiteRepositoryWithDB(db)
	service := user.NewService(repo)

	ctx := context.Background()

	// Create a new user
	createReq := user.CreateUserRequest{
		ID:         "user-123",
		Email:      "john.doe@example.com",
		GivenName:  "John",
		FamilyName: "Doe",
		Role:       "user",
	}

	createdUser, err := service.CreateUser(ctx, createReq)
	if err != nil {
		log.Fatal("Failed to create user:", err)
	}
	fmt.Printf("Created user: %+v\n", createdUser)

	// Get user by ID
	fetchedUser, err := service.GetUserByID(ctx, "user-123")
	if err != nil {
		log.Fatal("Failed to get user:", err)
	}
	fmt.Printf("Fetched user: %+v\n", fetchedUser)

	// Generate API key
	apiKey, err := service.GenerateAPIKey(ctx, "user-123", "john.doe@example.com")
	if err != nil {
		log.Fatal("Failed to generate API key:", err)
	}
	fmt.Printf("Generated API key: %s\n", apiKey)

	// Validate API key
	validatedUser, err := service.ValidateAPIKey(ctx, apiKey)
	if err != nil {
		log.Fatal("Failed to validate API key:", err)
	}
	fmt.Printf("API key validated for user: %+v\n", validatedUser)

	// List users
	users, err := service.ListUsers(ctx, 10, 0)
	if err != nil {
		log.Fatal("Failed to list users:", err)
	}
	fmt.Printf("Found %d users\n", len(users))
}

// createUsersTable creates the users table for the example
func createUsersTable(db *sql.DB) error {
	query := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		email TEXT UNIQUE NOT NULL,
		given_name TEXT,
		family_name TEXT,
		picture TEXT,
		role TEXT DEFAULT 'user',
		api_key TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`

	_, err := db.Exec(query)
	return err
}
