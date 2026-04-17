package domain

import "context"

// UserRepository is the port (interface) for user persistence.
// Implement this interface with your own adapter (PostgreSQL, MongoDB, Redis, etc.)
// to plug in real storage without changing any domain or application code.
type UserRepository interface {
	// Save persists a new User. Returns an error if the operation fails.
	Save(ctx context.Context, user *User) error

	// FindByEmail returns the User with the given email address.
	// Returns ErrUserNotFound if no match exists.
	FindByEmail(ctx context.Context, email string) (*User, error)

	// FindByID returns the User with the given UUID.
	// Returns ErrUserNotFound if no match exists.
	FindByID(ctx context.Context, id string) (*User, error)

	// ExistsByEmail returns true if a user with the given email is already registered.
	ExistsByEmail(ctx context.Context, email string) (bool, error)

	// FindAll returns every registered user. Intended for admin use only.
	FindAll(ctx context.Context) ([]*User, error)

	// FindByUsername returns the User whose username matches the given string (case-insensitive).
	// Returns ErrUserNotFound if no match exists.
	FindByUsername(ctx context.Context, username string) (*User, error)

	// Update overwrites the mutable fields of an existing User.
	// Returns ErrUserNotFound if the user does not exist.
	Update(ctx context.Context, user *User) error

	// Delete removes the User with the given UUID from the store.
	// Returns ErrUserNotFound if the user does not exist.
	Delete(ctx context.Context, id string) error
}

// TokenManager is the port (interface) for JWT token lifecycle management.
// The infrastructure/jwt package provides the default HMAC-SHA256 implementation.
type TokenManager interface {
	// GeneratePair creates a new access/refresh TokenPair for the given user.
	GeneratePair(user *User) (*TokenPair, error)

	// ValidateAccessToken parses and validates a signed access token string,
	// returning the embedded Claims on success.
	ValidateAccessToken(token string) (*Claims, error)

	// ValidateRefreshToken parses and validates a signed refresh token string,
	// returning the embedded Claims on success.
	ValidateRefreshToken(token string) (*Claims, error)
}
