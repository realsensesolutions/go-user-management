package user

import (
	"database/sql"
	"embed"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// Migration represents a database migration
type Migration struct {
	Version     int    `json:"version"`
	Name        string `json:"name"`
	UpSQL       string `json:"up_sql"`
	DownSQL     string `json:"down_sql"`
	Description string `json:"description"`
}

// MigrationStatus represents the status of migrations
type MigrationStatus struct {
	CurrentVersion    int         `json:"current_version"`
	LatestVersion     int         `json:"latest_version"`
	PendingMigrations []Migration `json:"pending_migrations"`
	IsUpToDate        bool        `json:"is_up_to_date"`
}

// GetAllMigrations returns all available migrations sorted by version
func GetAllMigrations() ([]Migration, error) {
	entries, err := migrationFiles.ReadDir("migrations")
	if err != nil {
		return nil, fmt.Errorf("failed to read migrations directory: %w", err)
	}

	migrationMap := make(map[int]*Migration)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}

		// Parse filename: 001_name.up.sql or 001_name.down.sql
		parts := strings.Split(name, "_")
		if len(parts) < 2 {
			continue
		}

		versionStr := parts[0]
		version, err := strconv.Atoi(versionStr)
		if err != nil {
			continue
		}

		content, err := migrationFiles.ReadFile("migrations/" + name)
		if err != nil {
			return nil, fmt.Errorf("failed to read migration file %s: %w", name, err)
		}

		// Get or create migration entry
		migration, exists := migrationMap[version]
		if !exists {
			migration = &Migration{
				Version: version,
				Name:    strings.Join(parts[1:], "_"),
			}
			migrationMap[version] = migration
		}

		// Determine if this is up or down migration
		if strings.Contains(name, ".up.sql") {
			migration.UpSQL = string(content)
			migration.Description = fmt.Sprintf("Migration %d: %s", version, strings.TrimSuffix(migration.Name, ".up.sql"))
		} else if strings.Contains(name, ".down.sql") {
			migration.DownSQL = string(content)
		}
	}

	// Convert map to sorted slice
	var migrations []Migration
	for _, migration := range migrationMap {
		migrations = append(migrations, *migration)
	}

	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})

	return migrations, nil
}

// GetCurrentSchemaVersion returns the current schema version from the database
func GetCurrentSchemaVersion(db *sql.DB) (int, error) {
	// Create schema_migrations table if it doesn't exist
	createTable := `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`
	if _, err := db.Exec(createTable); err != nil {
		return 0, fmt.Errorf("failed to create schema_migrations table: %w", err)
	}

	// Get the highest version number
	var version sql.NullInt64
	err := db.QueryRow("SELECT MAX(version) FROM schema_migrations").Scan(&version)
	if err != nil {
		return 0, fmt.Errorf("failed to get current schema version: %w", err)
	}

	if !version.Valid {
		return 0, nil // No migrations applied yet
	}

	return int(version.Int64), nil
}

// GetMigrationStatus returns the current migration status
func GetMigrationStatus(db *sql.DB) (*MigrationStatus, error) {
	currentVersion, err := GetCurrentSchemaVersion(db)
	if err != nil {
		return nil, fmt.Errorf("failed to get current schema version: %w", err)
	}

	allMigrations, err := GetAllMigrations()
	if err != nil {
		return nil, fmt.Errorf("failed to get all migrations: %w", err)
	}

	if len(allMigrations) == 0 {
		return &MigrationStatus{
			CurrentVersion: currentVersion,
			LatestVersion:  0,
			IsUpToDate:     true,
		}, nil
	}

	latestVersion := allMigrations[len(allMigrations)-1].Version

	// Find pending migrations
	var pendingMigrations []Migration
	for _, migration := range allMigrations {
		if migration.Version > currentVersion {
			pendingMigrations = append(pendingMigrations, migration)
		}
	}

	return &MigrationStatus{
		CurrentVersion:    currentVersion,
		LatestVersion:     latestVersion,
		PendingMigrations: pendingMigrations,
		IsUpToDate:        len(pendingMigrations) == 0,
	}, nil
}

// ValidateSchema checks if the current database schema matches requirements
func ValidateSchema(db *sql.DB) error {
	// Check if users table exists with required columns
	requiredColumns := []string{"id", "email", "given_name", "family_name", "picture", "role", "api_key", "created_at", "updated_at"}
	
	rows, err := db.Query("PRAGMA table_info(users)")
	if err != nil {
		return fmt.Errorf("failed to get table info: %w", err)
	}
	defer rows.Close()

	existingColumns := make(map[string]bool)
	for rows.Next() {
		var cid int
		var name, dataType string
		var notNull, pk int
		var defaultValue sql.NullString

		err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &pk)
		if err != nil {
			return fmt.Errorf("failed to scan column info: %w", err)
		}
		existingColumns[name] = true
	}

	if len(existingColumns) == 0 {
		return fmt.Errorf("users table does not exist")
	}

	// Check for missing columns
	var missingColumns []string
	for _, col := range requiredColumns {
		if !existingColumns[col] {
			missingColumns = append(missingColumns, col)
		}
	}

	if len(missingColumns) > 0 {
		return fmt.Errorf("missing required columns: %s", strings.Join(missingColumns, ", "))
	}

	return nil
}

// AutoMigrate automatically applies all pending migrations
// This should only be used in development environments
func AutoMigrate(db *sql.DB) error {
	status, err := GetMigrationStatus(db)
	if err != nil {
		return fmt.Errorf("failed to get migration status: %w", err)
	}

	if status.IsUpToDate {
		return nil // Nothing to do
	}

	// Apply each pending migration
	for _, migration := range status.PendingMigrations {
		if err := ApplyMigration(db, migration); err != nil {
			return fmt.Errorf("failed to apply migration %d: %w", migration.Version, err)
		}
	}

	return nil
}

// ApplyMigration applies a single migration
func ApplyMigration(db *sql.DB, migration Migration) error {
	// Start transaction
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()

	// Handle special case for migration 002 (adding missing columns)
	if migration.Version == 2 {
		if err := addMissingColumns(tx); err != nil {
			return fmt.Errorf("failed to add missing columns: %w", err)
		}
	}

	// Execute the migration SQL
	if migration.UpSQL != "" {
		if _, err := tx.Exec(migration.UpSQL); err != nil {
			return fmt.Errorf("failed to execute migration SQL: %w", err)
		}
	}

	// Record the migration as applied
	if _, err := tx.Exec("INSERT INTO schema_migrations (version) VALUES (?)", migration.Version); err != nil {
		return fmt.Errorf("failed to record migration: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit migration: %w", err)
	}

	return nil
}

// addMissingColumns adds missing columns to existing users table
func addMissingColumns(tx *sql.Tx) error {
	// Get existing columns
	rows, err := tx.Query("PRAGMA table_info(users)")
	if err != nil {
		return fmt.Errorf("failed to get table info: %w", err)
	}
	defer rows.Close()

	existingColumns := make(map[string]bool)
	for rows.Next() {
		var cid int
		var name, dataType string
		var notNull, pk int
		var defaultValue sql.NullString

		err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &pk)
		if err != nil {
			return fmt.Errorf("failed to scan column info: %w", err)
		}
		existingColumns[name] = true
	}

	// Define columns that might be missing
	columnsToAdd := map[string]string{
		"picture":    "TEXT DEFAULT ''",
		"role":       "TEXT DEFAULT 'user'",
		"created_at": "DATETIME DEFAULT CURRENT_TIMESTAMP",
		"updated_at": "DATETIME DEFAULT CURRENT_TIMESTAMP",
	}

	// Add missing columns
	for column, definition := range columnsToAdd {
		if !existingColumns[column] {
			alterSQL := fmt.Sprintf("ALTER TABLE users ADD COLUMN %s %s", column, definition)
			if _, err := tx.Exec(alterSQL); err != nil {
				return fmt.Errorf("failed to add column %s: %w", column, err)
			}
		}
	}

	// Update existing records to have proper timestamps if they're missing
	if !existingColumns["created_at"] {
		if _, err := tx.Exec("UPDATE users SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL"); err != nil {
			return fmt.Errorf("failed to update created_at: %w", err)
		}
	}

	if !existingColumns["updated_at"] {
		if _, err := tx.Exec("UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE updated_at IS NULL"); err != nil {
			return fmt.Errorf("failed to update updated_at: %w", err)
		}
	}

	return nil
}

// GetRequiredMigrations returns migrations that need to be applied (alias for GetMigrationStatus)
func GetRequiredMigrations(db *sql.DB) ([]Migration, error) {
	status, err := GetMigrationStatus(db)
	if err != nil {
		return nil, err
	}
	return status.PendingMigrations, nil
}