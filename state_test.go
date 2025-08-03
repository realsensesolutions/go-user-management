package user

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	database "github.com/realsensesolutions/go-database"
)

// TestStateRepository_StoreAndValidateState tests the core OAuth state storage workflow
// This validates that state can be stored and then retrieved/validated correctly
func TestStateRepository_StoreAndValidateState(t *testing.T) {
	// Setup test database
	tempDir := t.TempDir()
	dbFile := filepath.Join(tempDir, "test_state.db")
	originalDBFile := os.Getenv("DATABASE_FILE")
	os.Setenv("DATABASE_FILE", dbFile)
	defer func() {
		if originalDBFile == "" {
			os.Unsetenv("DATABASE_FILE")
		} else {
			os.Setenv("DATABASE_FILE", originalDBFile)
		}
	}()

	// Create database and run migrations
	db, err := database.GetDB()
	if err != nil {
		t.Fatalf("failed to create test database: %v", err)
	}
	defer db.Close()

	// Run migrations to create oauth_states table
	if err := AutoMigrate(db); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}

	// Create state repository using the service pattern
	stateRepo := NewSQLiteStateRepository(database.GetDB)

	// Test data
	testState := "test-state-12345"
	testRedirectURL := "https://localhost:8000/dashboard"
	expiresAt := time.Now().Add(5 * time.Minute)

	// Step 1: Store the state
	err = stateRepo.StoreState(testState, testRedirectURL, expiresAt)
	if err != nil {
		t.Fatalf("failed to store state: %v", err)
	}

	// Step 2: Validate and retrieve the state
	retrievedURL, isValid := stateRepo.ValidateAndRemoveState(testState)
	if !isValid {
		t.Fatal("expected state to be valid, but validation failed")
	}

	if retrievedURL != testRedirectURL {
		t.Errorf("expected redirect URL '%s', got '%s'", testRedirectURL, retrievedURL)
	}

	// Step 3: Verify state is removed after validation (one-time use)
	_, isValidSecondTime := stateRepo.ValidateAndRemoveState(testState)
	if isValidSecondTime {
		t.Error("expected state to be invalid after first use, but it was still valid")
	}

	t.Logf("✅ OAuth state storage and validation working correctly")
}
