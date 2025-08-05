package user

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	database "github.com/realsensesolutions/go-database"
)

// SQLiteStateRepository handles OAuth state persistence with SQLite
type SQLiteStateRepository struct {
	// No dependencies - uses database.GetDB() directly like all other repositories
}

// NewSQLiteStateRepository creates a new SQLite-based state repository
func NewSQLiteStateRepository() StateRepository {
	return &SQLiteStateRepository{}
}

// StoreState stores an OAuth state with optional redirect URL
func (r *SQLiteStateRepository) StoreState(state string, redirectURL string, expiresAt time.Time) error {
	// Get fresh database connection
	db, err := database.GetDB()
	if err != nil {
		return err
	}
	defer db.Close()

	// Generate a cryptographically secure random ID to prevent collisions
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return fmt.Errorf("failed to generate random ID: %w", err)
	}
	id := fmt.Sprintf("oauth_state_%s", hex.EncodeToString(randomBytes))

	query := `
		INSERT INTO oauth_states (id, state, redirect_url, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?)
	`

	// Use retry logic to handle SQLite concurrency issues
	_, err = database.ExecWithRetry(db, query, id, state, redirectURL, expiresAt.Unix(), time.Now().Unix())
	if err != nil {
		return fmt.Errorf("failed to store OAuth state: %w", err)
	}

	return nil
}

// ValidateAndRemoveState validates a state and returns the associated redirect URL
func (r *SQLiteStateRepository) ValidateAndRemoveState(state string) (string, bool) {
	// Get fresh database connection
	db, err := database.GetDB()
	if err != nil {
		return "", false
	}
	defer db.Close()

	var redirectURL string
	var expiresAt int64

	// First, get the state and check if it exists and hasn't expired
	query := `
		SELECT redirect_url, expires_at 
		FROM oauth_states 
		WHERE state = ? AND expires_at > ?
	`

	err = database.QueryRowWithRetry(db, query, state, time.Now().Unix()).Scan(&redirectURL, &expiresAt)
	if err != nil {
		if err == sql.ErrNoRows {
			// State doesn't exist or has expired
			return "", false
		}
		// Database error
		return "", false
	}

	// State is valid, now remove it (one-time use)
	deleteQuery := `DELETE FROM oauth_states WHERE state = ?`
	_, err = database.ExecWithRetry(db, deleteQuery, state)
	if err != nil {
		// Log error but don't fail the validation since we found the state
		fmt.Printf("Warning: failed to delete OAuth state: %v\n", err)
	}

	return redirectURL, true
}

// CleanupExpiredStates removes expired OAuth states
func (r *SQLiteStateRepository) CleanupExpiredStates() error {
	// Get fresh database connection
	db, err := database.GetDB()
	if err != nil {
		return err
	}
	defer db.Close()

	query := `DELETE FROM oauth_states WHERE expires_at <= ?`

	_, err = database.ExecWithRetry(db, query, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("failed to cleanup expired OAuth states: %w", err)
	}

	return nil
}
