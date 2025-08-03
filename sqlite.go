package user

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/realsensesolutions/go-database"
)

// sqliteRepository implements the Repository interface for SQLite
type sqliteRepository struct {
	getDB func() (*sql.DB, error)
}

// NewSQLiteRepository creates a new SQLite repository with a database connection function
func NewSQLiteRepository(getDB func() (*sql.DB, error)) Repository {
	return &sqliteRepository{getDB: getDB}
}

// NewSQLiteRepositoryWithDB creates a new SQLite repository with an existing database connection
func NewSQLiteRepositoryWithDB(db *sql.DB) Repository {
	return &sqliteRepository{
		getDB: func() (*sql.DB, error) {
			return db, nil
		},
	}
}

// GetUserByID retrieves a user by ID
func (r *sqliteRepository) GetUserByID(userID string) (*User, error) {
	db, err := r.getDB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database connection: %w", err)
	}
	defer db.Close()

	// Note: id IS the email address in the new schema
	query := `SELECT id, id as email, given_name, family_name, picture, role, api_key, created_at, updated_at 
	          FROM users WHERE id = ?`

	var user User
	err = database.QueryRowWithRetry(db, query, userID).Scan(
		&user.ID,
		&user.Email,
		&user.GivenName,
		&user.FamilyName,
		&user.Picture,
		&user.Role,
		&user.APIKey,
		&user.CreatedAt,
		&user.UpdatedAt,
	)


	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

// GetUserByEmail retrieves a user by email
func (r *sqliteRepository) GetUserByEmail(email string) (*User, error) {
	db, err := r.getDB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database connection: %w", err)
	}
	defer db.Close()

	// Note: id IS the email address in the new schema, so WHERE id = email
	query := `SELECT id, id as email, given_name, family_name, picture, role, api_key, created_at, updated_at 
	          FROM users WHERE id = ?`

	var user User
	err = database.QueryRowWithRetry(db, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.GivenName,
		&user.FamilyName,
		&user.Picture,
		&user.Role,
		&user.APIKey,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	return &user, nil
}

// CreateUser creates a new user
func (r *sqliteRepository) CreateUser(req CreateUserRequest) (*User, error) {
	db, err := r.getDB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database connection: %w", err)
	}
	defer db.Close()

	now := time.Now()

	// Set default role if not provided
	role := req.Role
	if role == "" {
		role = "user"
	}

	// Note: id IS the email address in the new schema, use email as the id
	// Use INSERT OR REPLACE to handle duplicate users gracefully
	query := `INSERT OR REPLACE INTO users (id, given_name, family_name, picture, role, created_at, updated_at)
	          VALUES (?, ?, ?, ?, ?, 
	              COALESCE((SELECT created_at FROM users WHERE id = ?), ?),
	              ?)`

	idToUse := req.Email // Use email as the primary key
	if idToUse == "" && req.ID != "" {
		idToUse = req.ID // Fallback to ID if email not provided
	}

	_, err = database.ExecWithRetry(db, query,
		idToUse, req.GivenName, req.FamilyName,
		req.Picture, role,
		idToUse, now, // For the COALESCE subquery and created_at default
		now, // For updated_at
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create/update user: %w", err)
	}

	// Return the created user
	return r.GetUserByID(idToUse)
}

// UpdateUser updates an existing user
func (r *sqliteRepository) UpdateUser(req UpdateUserRequest) (*User, error) {
	db, err := r.getDB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database connection: %w", err)
	}
	defer db.Close()

	// Build dynamic update query based on provided fields
	updates := []string{}
	args := []interface{}{}

	if req.Email != nil {
		updates = append(updates, "email = ?")
		args = append(args, *req.Email)
	}
	if req.GivenName != nil {
		updates = append(updates, "given_name = ?")
		args = append(args, *req.GivenName)
	}
	if req.FamilyName != nil {
		updates = append(updates, "family_name = ?")
		args = append(args, *req.FamilyName)
	}
	if req.Picture != nil {
		updates = append(updates, "picture = ?")
		args = append(args, *req.Picture)
	}
	if req.Role != nil {
		updates = append(updates, "role = ?")
		args = append(args, *req.Role)
	}

	if len(updates) == 0 {
		return r.GetUserByID(req.ID) // No updates, return existing user
	}

	// Add updated_at
	updates = append(updates, "updated_at = ?")
	args = append(args, time.Now())

	// Add WHERE clause
	args = append(args, req.ID)

	query := fmt.Sprintf("UPDATE users SET %s WHERE id = ?",
		fmt.Sprintf("%s", updates[0]))
	for i := 1; i < len(updates); i++ {
		query = fmt.Sprintf("%s, %s", query, updates[i])
	}

	_, err = database.ExecWithRetry(db, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	return r.GetUserByID(req.ID)
}

// DeleteUser deletes a user by ID
func (r *sqliteRepository) DeleteUser(userID string) error {
	db, err := r.getDB()
	if err != nil {
		return fmt.Errorf("failed to get database connection: %w", err)
	}
	defer db.Close()

	query := `DELETE FROM users WHERE id = ?`

	result, err := database.ExecWithRetry(db, query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return ErrUserNotFound
	}

	return nil
}

// GetAPIKey retrieves the API key for a user
func (r *sqliteRepository) GetAPIKey(userID string) (string, error) {
	db, err := r.getDB()
	if err != nil {
		return "", fmt.Errorf("failed to get database connection: %w", err)
	}
	defer db.Close()

	query := `SELECT api_key FROM users WHERE id = ?`

	var apiKey string
	err = database.QueryRowWithRetry(db, query, userID).Scan(&apiKey)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", ErrUserNotFound
		}
		return "", fmt.Errorf("failed to get API key: %w", err)
	}

	return apiKey, nil
}

// UpsertAPIKey creates or updates the API key for a user
func (r *sqliteRepository) UpsertAPIKey(userID, email, apiKey string) error {
	db, err := r.getDB()
	if err != nil {
		return fmt.Errorf("failed to get database connection: %w", err)
	}
	defer db.Close()

	// Try to update existing user first
	updateQuery := `UPDATE users SET api_key = ?, updated_at = ? WHERE id = ?`
	result, err := database.ExecWithRetry(db, updateQuery, apiKey, time.Now(), userID)
	if err != nil {
		return fmt.Errorf("failed to update API key: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	// If no rows were affected, the user doesn't exist, so create them
	if rowsAffected == 0 {
		now := time.Now()
		// Note: id IS the email address in the new schema
		// Use INSERT OR REPLACE to handle any race conditions
		insertQuery := `INSERT OR REPLACE INTO users (id, given_name, family_name, api_key, created_at, updated_at)
		               VALUES (?, ?, ?, ?, ?, ?)`

		idToUse := email // Use email as the primary key
		if idToUse == "" && userID != "" {
			idToUse = userID // Fallback to userID if email not provided
		}

		_, err = database.ExecWithRetry(db, insertQuery, idToUse, "Unknown", "User", apiKey, now, now)
		if err != nil {
			return fmt.Errorf("failed to create user with API key: %w", err)
		}
	}

	return nil
}

// GetUserByAPIKey retrieves a user by their API key
func (r *sqliteRepository) GetUserByAPIKey(apiKey string) (*User, error) {
	db, err := r.getDB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database connection: %w", err)
	}
	defer db.Close()

	// Note: id IS the email address in the new schema
	query := `SELECT id, id as email, given_name, family_name, picture, role, api_key, created_at, updated_at 
	          FROM users WHERE api_key = ?`

	var user User
	err = database.QueryRowWithRetry(db, query, apiKey).Scan(
		&user.ID,
		&user.Email,
		&user.GivenName,
		&user.FamilyName,
		&user.Picture,
		&user.Role,
		&user.APIKey,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by API key: %w", err)
	}

	return &user, nil
}

// ListUsers retrieves a list of users with pagination
func (r *sqliteRepository) ListUsers(ctx context.Context, limit, offset int) ([]*User, error) {
	db, err := r.getDB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database connection: %w", err)
	}
	defer db.Close()

	query := `SELECT id, id as email, given_name, family_name, picture, role, api_key, created_at, updated_at 
	          FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?`

	rows, err := database.QueryWithRetry(db, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		var user User
		err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.GivenName,
			&user.FamilyName,
			&user.Picture,
			&user.Role,
			&user.APIKey,
			&user.CreatedAt,
			&user.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}
		users = append(users, &user)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate users: %w", err)
	}

	return users, nil
}
