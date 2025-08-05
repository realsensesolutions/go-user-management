package user

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
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
	log.Printf("🔍 [StateRepo] Starting StoreState for state: %s", state[:8]+"...")

	// Get fresh database connection
	log.Printf("🔄 [StateRepo] Getting database connection...")
	dbStartTime := time.Now()
	db, err := database.GetDB()
	dbDuration := time.Since(dbStartTime)

	if err != nil {
		log.Printf("❌ [StateRepo] Failed to get database connection after %v: %v", dbDuration, err)
		return err
	}
	log.Printf("✅ [StateRepo] Got database connection in %v", dbDuration)
	defer func() {
		log.Printf("🔄 [StateRepo] Closing database connection...")
		db.Close()
	}()

	// Generate a cryptographically secure random ID to prevent collisions
	log.Printf("🔄 [StateRepo] Generating random ID...")
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		log.Printf("❌ [StateRepo] Failed to generate random ID: %v", err)
		return fmt.Errorf("failed to generate random ID: %w", err)
	}
	id := fmt.Sprintf("oauth_state_%s", hex.EncodeToString(randomBytes))
	log.Printf("✅ [StateRepo] Generated ID: %s", id)

	query := `
		INSERT INTO oauth_states (id, state, redirect_url, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?)
	`

	// Use retry logic to handle SQLite concurrency issues
	log.Printf("🔄 [StateRepo] About to execute INSERT with retry logic...")
	insertStartTime := time.Now()
	_, err = database.ExecWithRetry(db, query, id, state, redirectURL, expiresAt.Unix(), time.Now().Unix())
	insertDuration := time.Since(insertStartTime)

	if err != nil {
		log.Printf("❌ [StateRepo] INSERT failed after %v: %v", insertDuration, err)
		return fmt.Errorf("failed to store OAuth state: %w", err)
	}

	log.Printf("✅ [StateRepo] INSERT completed successfully in %v", insertDuration)
	return nil
}

// ValidateAndRemoveState validates a state and returns the associated redirect URL
func (r *SQLiteStateRepository) ValidateAndRemoveState(state string) (string, bool) {
	log.Printf("🔍 [StateRepo] Starting ValidateAndRemoveState for state: %s", state[:8]+"...")

	// Get fresh database connection
	log.Printf("🔄 [StateRepo] Getting database connection for validation...")
	dbStartTime := time.Now()
	db, err := database.GetDB()
	dbDuration := time.Since(dbStartTime)

	if err != nil {
		log.Printf("❌ [StateRepo] Failed to get database connection for validation after %v: %v", dbDuration, err)
		return "", false
	}
	log.Printf("✅ [StateRepo] Got database connection for validation in %v", dbDuration)
	defer func() {
		log.Printf("🔄 [StateRepo] Closing database connection for validation...")
		db.Close()
	}()

	var redirectURL string
	var expiresAt int64

	// First, get the state and check if it exists and hasn't expired
	query := `
		SELECT redirect_url, expires_at 
		FROM oauth_states 
		WHERE state = ? AND expires_at > ?
	`

	log.Printf("🔄 [StateRepo] About to query for state validation...")
	queryStartTime := time.Now()
	err = database.QueryRowWithRetry(db, query, state, time.Now().Unix()).Scan(&redirectURL, &expiresAt)
	queryDuration := time.Since(queryStartTime)

	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("⚠️ [StateRepo] State not found or expired after %v", queryDuration)
			return "", false
		}
		log.Printf("❌ [StateRepo] Database error during validation after %v: %v", queryDuration, err)
		return "", false
	}
	log.Printf("✅ [StateRepo] State validation query completed in %v", queryDuration)

	// State is valid, now remove it (one-time use)
	deleteQuery := `DELETE FROM oauth_states WHERE state = ?`
	log.Printf("🔄 [StateRepo] About to delete validated state...")
	deleteStartTime := time.Now()
	_, err = database.ExecWithRetry(db, deleteQuery, state)
	deleteDuration := time.Since(deleteStartTime)

	if err != nil {
		log.Printf("❌ [StateRepo] Failed to delete OAuth state after %v: %v", deleteDuration, err)
		// Log error but don't fail the validation since we found the state
	} else {
		log.Printf("✅ [StateRepo] State deleted successfully in %v", deleteDuration)
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
