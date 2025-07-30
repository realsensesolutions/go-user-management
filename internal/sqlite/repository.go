package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	user "github.com/realsensesolutions/go-user-management"
	_ "modernc.org/sqlite"
)

// Repository implements the user.Repository interface for SQLite
type Repository struct {
	db *sql.DB
}

// NewRepository creates a new SQLite user repository
func NewRepository(db *sql.DB) user.Repository {
	return &Repository{db: db}
}

// GetUserByID retrieves a user by their ID
func (r *Repository) GetUserByID(userID string) (*user.User, error) {
	query := `SELECT id, email, given_name, family_name, picture, role, created_at, updated_at 
	          FROM users WHERE id = ?`
	
	var u user.User
	err := r.db.QueryRow(query, userID).Scan(
		&u.ID, &u.Email, &u.GivenName, &u.FamilyName, 
		&u.Picture, &u.Role, &u.CreatedAt, &u.UpdatedAt,
	)
	
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, user.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}
	
	return &u, nil
}

// GetUserByEmail retrieves a user by their email address
func (r *Repository) GetUserByEmail(email string) (*user.User, error) {
	query := `SELECT id, email, given_name, family_name, picture, role, created_at, updated_at 
	          FROM users WHERE email = ?`
	
	var u user.User
	err := r.db.QueryRow(query, email).Scan(
		&u.ID, &u.Email, &u.GivenName, &u.FamilyName, 
		&u.Picture, &u.Role, &u.CreatedAt, &u.UpdatedAt,
	)
	
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, user.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}
	
	return &u, nil
}

// CreateUser creates a new user
func (r *Repository) CreateUser(req user.CreateUserRequest) (*user.User, error) {
	now := time.Now()
	
	query := `INSERT INTO users (id, email, given_name, family_name, picture, role, created_at, updated_at)
	          VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	
	_, err := r.db.Exec(query, 
		req.ID, req.Email, req.GivenName, req.FamilyName, 
		req.Picture, req.Role, now, now,
	)
	
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}
	
	// Return the created user
	return r.GetUserByID(req.ID)
}

// UpdateUser updates an existing user
func (r *Repository) UpdateUser(req user.UpdateUserRequest) (*user.User, error) {
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
	
	_, err := r.db.Exec(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}
	
	return r.GetUserByID(req.ID)
}

// DeleteUser deletes a user by ID
func (r *Repository) DeleteUser(userID string) error {
	query := `DELETE FROM users WHERE id = ?`
	
	result, err := r.db.Exec(query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	
	if rowsAffected == 0 {
		return user.ErrUserNotFound
	}
	
	return nil
}

// GetAPIKey returns a stored API key for a user or empty string if none
func (r *Repository) GetAPIKey(userID string) (string, error) {
	query := `SELECT api_key FROM users WHERE id = ?`
	
	var apiKey sql.NullString
	err := r.db.QueryRow(query, userID).Scan(&apiKey)
	
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil // No API key found, return empty string
		}
		return "", fmt.Errorf("failed to get API key: %w", err)
	}
	
	return apiKey.String, nil
}

// UpsertAPIKey saves the API key for the given user, inserting user row with minimal data if necessary
func (r *Repository) UpsertAPIKey(userID, email, apiKey string) error {
	// Try to update first
	updateQuery := `UPDATE users SET api_key = ? WHERE id = ?`
	result, err := r.db.Exec(updateQuery, apiKey, userID)
	if err != nil {
		return fmt.Errorf("failed to update API key: %w", err)
	}
	
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	
	if rowsAffected == 0 {
		// User doesn't exist, insert minimal user record
		now := time.Now()
		insertQuery := `INSERT OR IGNORE INTO users (id, email, api_key, created_at, updated_at)
		                VALUES (?, ?, ?, ?, ?)`
		_, err = r.db.Exec(insertQuery, userID, email, apiKey, now, now)
		if err != nil {
			return fmt.Errorf("failed to insert user with API key: %w", err)
		}
	}
	
	return nil
}

// GetUserByAPIKey finds a user by their API key
func (r *Repository) GetUserByAPIKey(apiKey string) (*user.User, error) {
	query := `SELECT id, email, given_name, family_name, picture, role, created_at, updated_at 
	          FROM users WHERE api_key = ?`
	
	var u user.User
	err := r.db.QueryRow(query, apiKey).Scan(
		&u.ID, &u.Email, &u.GivenName, &u.FamilyName, 
		&u.Picture, &u.Role, &u.CreatedAt, &u.UpdatedAt,
	)
	
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, user.ErrInvalidAPIKey
		}
		return nil, fmt.Errorf("failed to get user by API key: %w", err)
	}
	
	return &u, nil
}

// ListUsers returns a list of users with pagination
func (r *Repository) ListUsers(ctx context.Context, limit, offset int) ([]*user.User, error) {
	query := `SELECT id, email, given_name, family_name, picture, role, created_at, updated_at 
	          FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?`
	
	rows, err := r.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()
	
	var users []*user.User
	for rows.Next() {
		var u user.User
		err := rows.Scan(
			&u.ID, &u.Email, &u.GivenName, &u.FamilyName, 
			&u.Picture, &u.Role, &u.CreatedAt, &u.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}
		users = append(users, &u)
	}
	
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating users: %w", err)
	}
	
	return users, nil
}