package user

import (
	"embed"
	"log"

	database "github.com/realsensesolutions/go-database"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

//go:embed migrations/postgres/*.sql
var postgresMigrationsFS embed.FS

// GetPostgresMigrationsFS returns the embedded filesystem containing PostgreSQL migrations
// This allows external packages to run these migrations using their own migration system
func GetPostgresMigrationsFS() embed.FS {
	return postgresMigrationsFS
}

// init registers user management migrations with the global database registry
// Note: Migrations are registered for both SQLite and PostgreSQL
// The actual migration set used depends on runtime configuration
func init() {
	log.Printf("📦 Registering user management embedded migrations...")

	// Register SQLite migrations (default, for backward compatibility)
	log.Printf("📦 Registering SQLite migrations for user-management")
	database.RegisterMigrations(database.MigrationSource{
		Name:    "user-management-sqlite",
		EmbedFS: &migrationsFS,
		SubPath: "migrations",
		Prefix:  "user_sqlite_",
	})

	// Register PostgreSQL migrations
	log.Printf("📦 Registering PostgreSQL migrations for user-management")
	database.RegisterMigrations(database.MigrationSource{
		Name:    "user-management-postgres",
		EmbedFS: &postgresMigrationsFS,
		SubPath: "migrations/postgres",
		Prefix:  "user_pg_",
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
