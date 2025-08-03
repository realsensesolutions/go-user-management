package user

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	database "github.com/realsensesolutions/go-database"
)

// TestOAuth2Service_GenerateAuthURL_StoresState tests that GenerateAuthURL actually stores state
// This is the CORE behavior that's failing in the real system
func TestOAuth2Service_GenerateAuthURL_StoresState(t *testing.T) {
	// Setup test database
	tempDir := t.TempDir()
	dbFile := filepath.Join(tempDir, "test_oauth2.db")
	originalDBFile := os.Getenv("DATABASE_FILE")
	os.Setenv("DATABASE_FILE", dbFile)
	defer func() {
		if originalDBFile == "" {
			os.Unsetenv("DATABASE_FILE")
		} else {
			os.Setenv("DATABASE_FILE", originalDBFile)
		}
	}()

	// Set up ALL required environment variables for OAuth2
	requiredEnvs := map[string]string{
		"COGNITO_CLIENT_ID":     "test-client-id",
		"COGNITO_CLIENT_SECRET": "test-client-secret",
		"COGNITO_USER_POOL_ID":  "us-east-1_TestPool",
		"COGNITO_REDIRECT_URI":  "https://localhost:3000/oauth2/idpresponse",
		"AWS_REGION":            "us-east-1",
	}

	for key, value := range requiredEnvs {
		os.Setenv(key, value)
	}
	defer func() {
		for key := range requiredEnvs {
			os.Unsetenv(key)
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

	// Create OAuth2 service components
	stateRepo := NewSQLiteStateRepository(database.GetDB)
	mockUserService := NewService(NewSQLiteRepository(database.GetDB))
	oauth2Config := &OAuth2Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectPath: "/oauth2/idpresponse",
		Scopes:       []string{"openid", "email", "profile"},
		ProviderURL:  "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TestPool",
	}

	// Create OAuth2 service
	oauth2Service := NewOAuth2Service(mockUserService, stateRepo, oauth2Config)

	// Test data
	testRedirectURL := "https://localhost:8000/dashboard"

	// Call GenerateAuthURL - this SHOULD store state
	authURL, err := oauth2Service.GenerateAuthURL(testRedirectURL)
	if err != nil {
		t.Fatalf("GenerateAuthURL failed: %v", err)
	}

	// Verify URL was generated
	if authURL == "" {
		t.Fatal("GenerateAuthURL returned empty URL")
	}

	if !strings.Contains(authURL, "cognito-idp") {
		t.Errorf("Expected Cognito URL, got: %s", authURL)
	}

	// CRITICAL: Verify state was actually stored in database
	db2, err := database.GetDB()
	if err != nil {
		t.Fatalf("failed to get database: %v", err)
	}
	defer db2.Close()

	var stateCount int
	err = database.QueryRowWithRetry(db2, "SELECT COUNT(*) FROM oauth_states").Scan(&stateCount)
	if err != nil {
		t.Fatalf("failed to count states: %v", err)
	}

	if stateCount == 0 {
		t.Fatal("❌ CRITICAL: GenerateAuthURL did NOT store state in database")
	}

	t.Logf("✅ SUCCESS: GenerateAuthURL stored %d state(s) in database", stateCount)
	t.Logf("✅ Generated auth URL: %s", authURL)
}
