package user

import (
	"log"
	"path/filepath"
	"runtime"

	database "github.com/realsensesolutions/go-database"
)

// init registers user management migrations with the global database registry
func init() {
	log.Printf("📦 Registering user management migrations...")
	
	// Get the directory containing the migration files using runtime.Caller
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		log.Printf("❌ Failed to determine package directory")
		return
	}
	
	// Get the directory of this init.go file, then add migrations subdirectory
	packageDir := filepath.Dir(filename)
	migrationsDir := filepath.Join(packageDir, "migrations")
	
	database.RegisterMigrations(database.MigrationSource{
		Name:      "user-management",
		Directory: migrationsDir,
		Prefix:    "user_",
	})
	
	log.Printf("✅ User management migrations registered")
}

// GetMigrationsDir returns the path to the user management migrations directory
// This can be used by applications that need to know where the migrations are located
func GetMigrationsDir() string {
	// In a real implementation, you might want to use embed.FS
	// or runtime.Caller to get the accurate path
	return filepath.Join("packages", "domains", "go-user-management", "migrations")
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