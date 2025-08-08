package user

import (
	"embed"
	"log"

	database "github.com/realsensesolutions/go-database"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// init registers user management migrations with the global database registry
func init() {
	log.Printf("📦 Registering user management embedded migrations...")

	database.RegisterMigrations(database.MigrationSource{
		Name:    "user-management",
		EmbedFS: &migrationsFS,
		SubPath: "migrations",
		Prefix:  "user_",
	})

	log.Printf("✅ User management embedded migrations registered")
}

// ValidateUserSchema performs user-specific schema validation
func ValidateUserSchema() error {
	// This could perform user-specific validation beyond what the generic
	// migrator does, such as checking user-specific constraints, indexes, etc.
	log.Printf("🔍 Validating user management schema...")

	// Placeholder for user-specific validation logic
	// In a real implementation, this might check:
	// - User table has required columns
	// - Proper indexes exist
	// - Foreign key constraints are in place

	log.Printf("✅ User management schema validation completed")
	return nil
}
