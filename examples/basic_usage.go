package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"

	user "github.com/realsensesolutions/go-user-management"
	_ "modernc.org/sqlite"
)

var testDBFile string

// testGetDB returns a new connection to our test database
// This matches the expected pattern where each call gets a fresh connection
func testGetDB() (*sql.DB, error) {
	// Create a new connection each time (matches production pattern)
	return sql.Open("sqlite", testDBFile)
}

func main() {
	// Create temporary database file
	tmpFile, err := os.CreateTemp("", "user_example_*.db")
	if err != nil {
		log.Fatal("Failed to create temp file:", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()
	
	testDBFile = tmpFile.Name()

	// Open initial connection for migrations
	testDB, err := sql.Open("sqlite", testDBFile)
	if err != nil {
		log.Fatal("Failed to open database:", err)
	}

	// Create users table using the embedded migrations
	if err := user.AutoMigrate(testDB); err != nil {
		log.Fatal("Failed to run migrations:", err)
	}
	testDB.Close()

	// Create service using the same pattern as the backend
	repo := user.NewSQLiteRepository(testGetDB)
	service := user.NewService(repo)

	ctx := context.Background()

	// Create a new user (ID should be the email in the new schema)
	email := "john.doe@example.com"
	createReq := user.CreateUserRequest{
		ID:         email,
		Email:      email,
		GivenName:  "John",
		FamilyName: "Doe",
		Role:       "user",
	}

	createdUser, err := service.CreateUser(ctx, createReq)
	if err != nil {
		log.Fatal("Failed to create user:", err)
	}
	fmt.Printf("Created user: %+v\n", createdUser)

	// Get user by ID (which is the email)
	fetchedUser, err := service.GetUserByID(ctx, email)
	if err != nil {
		log.Fatal("Failed to get user:", err)
	}
	fmt.Printf("Fetched user: %+v\n", fetchedUser)

	// Generate API key
	apiKey, err := service.GenerateAPIKey(ctx, email, email)
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

