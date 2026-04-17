// Package repository provides infrastructure adapters for domain.UserRepository.
package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	// MySQL driver — imported for its side-effect (registering the "mysql" driver).
	_ "github.com/go-sql-driver/mysql"

	"github.com/rockefeller2021/usuario-auth/domain"
)

// MySQLUserRepository is a MySQL-backed implementation of domain.UserRepository.
// It uses database/sql directly (no ORM) for full control over queries and
// minimal dependency surface.
type MySQLUserRepository struct {
	db *sql.DB
}

// NewMySQLUserRepository opens a MySQL connection pool, verifies connectivity
// with a Ping, and returns a ready-to-use repository.
//
// dsn format: "user:password@tcp(host:port)/dbname?parseTime=true&charset=utf8mb4"
func NewMySQLUserRepository(dsn string) (*MySQLUserRepository, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("mysql: opening connection: %w", err)
	}

	// Tuning the connection pool for typical API workloads.
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(5 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("mysql: ping failed (check DSN / server status): %w", err)
	}

	return &MySQLUserRepository{db: db}, nil
}

// Close releases all database connections. Call this on application shutdown.
func (r *MySQLUserRepository) Close() error {
	return r.db.Close()
}

// ── UserRepository interface ──────────────────────────────────────────────────

const userColumns = `id, username, email, password_hash, role, is_active, created_at, updated_at`

// scanUser maps a sql.Row / sql.Rows into a domain.User.
func scanUser(s interface {
	Scan(...any) error
}) (*domain.User, error) {
	u := &domain.User{}
	var isActive int8
	err := s.Scan(
		&u.ID,
		&u.Username,
		&u.Email,
		&u.PasswordHash,
		&u.Role,
		&isActive,
		&u.CreatedAt,
		&u.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	u.IsActive = isActive == 1
	return u, nil
}

// Save inserts a new user record into the database.
func (r *MySQLUserRepository) Save(ctx context.Context, u *domain.User) error {
	const q = `
		INSERT INTO users (id, username, email, password_hash, role, is_active, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	isActive := 0
	if u.IsActive {
		isActive = 1
	}

	_, err := r.db.ExecContext(ctx, q,
		u.ID, u.Username, u.Email, u.PasswordHash,
		string(u.Role), isActive, u.CreatedAt, u.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("mysql save: %w", err)
	}
	return nil
}

// FindByEmail returns the user with the matching email or domain.ErrUserNotFound.
func (r *MySQLUserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	const q = `SELECT ` + userColumns + ` FROM users WHERE email = ? LIMIT 1`
	row := r.db.QueryRowContext(ctx, q, email)
	u, err := scanUser(row)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("%w: email=%s", domain.ErrUserNotFound, email)
	}
	if err != nil {
		return nil, fmt.Errorf("mysql find_by_email: %w", err)
	}
	return u, nil
}

// FindByID returns the user with the matching UUID or domain.ErrUserNotFound.
func (r *MySQLUserRepository) FindByID(ctx context.Context, id string) (*domain.User, error) {
	const q = `SELECT ` + userColumns + ` FROM users WHERE id = ? LIMIT 1`
	row := r.db.QueryRowContext(ctx, q, id)
	u, err := scanUser(row)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("%w: id=%s", domain.ErrUserNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("mysql find_by_id: %w", err)
	}
	return u, nil
}

// ExistsByEmail returns true if a user with the given email already exists.
func (r *MySQLUserRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	const q = `SELECT EXISTS(SELECT 1 FROM users WHERE email = ?)`
	var exists bool
	if err := r.db.QueryRowContext(ctx, q, email).Scan(&exists); err != nil {
		return false, fmt.Errorf("mysql exists_by_email: %w", err)
	}
	return exists, nil
}

// FindAll returns every user in the database. Intended for admin use only.
func (r *MySQLUserRepository) FindAll(ctx context.Context) ([]*domain.User, error) {
	const q = `SELECT ` + userColumns + ` FROM users ORDER BY created_at DESC`
	rows, err := r.db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("mysql find_all: %w", err)
	}
	defer rows.Close()

	var users []*domain.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("mysql find_all scan: %w", err)
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("mysql find_all rows: %w", err)
	}
	return users, nil
}

// FindByUsername performs a case-insensitive search by username.
func (r *MySQLUserRepository) FindByUsername(ctx context.Context, username string) (*domain.User, error) {
	const q = `SELECT ` + userColumns + ` FROM users WHERE LOWER(username) = ? LIMIT 1`
	row := r.db.QueryRowContext(ctx, q, strings.ToLower(username))
	u, err := scanUser(row)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("%w: username=%s", domain.ErrUserNotFound, username)
	}
	if err != nil {
		return nil, fmt.Errorf("mysql find_by_username: %w", err)
	}
	return u, nil
}

// Update overwrites the mutable fields of an existing user.
func (r *MySQLUserRepository) Update(ctx context.Context, u *domain.User) error {
	const q = `
		UPDATE users
		SET username = ?, email = ?, role = ?, is_active = ?, updated_at = ?
		WHERE id = ?`

	isActive := 0
	if u.IsActive {
		isActive = 1
	}

	res, err := r.db.ExecContext(ctx, q,
		u.Username, u.Email, string(u.Role), isActive, u.UpdatedAt, u.ID,
	)
	if err != nil {
		return fmt.Errorf("mysql update: %w", err)
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("mysql update rows_affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: id=%s", domain.ErrUserNotFound, u.ID)
	}
	return nil
}

// Delete permanently removes a user from the database.
func (r *MySQLUserRepository) Delete(ctx context.Context, id string) error {
	const q = `DELETE FROM users WHERE id = ?`
	res, err := r.db.ExecContext(ctx, q, id)
	if err != nil {
		return fmt.Errorf("mysql delete: %w", err)
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("mysql delete rows_affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: id=%s", domain.ErrUserNotFound, id)
	}
	return nil
}
