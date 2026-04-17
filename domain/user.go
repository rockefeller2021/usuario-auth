// Package domain contains the core business entities for the usuario-auth library.
package domain

import (
	"fmt"
	"time"
)

// Role represents the authorization level of a User.
type Role string

const (
	// RoleAdmin grants full access to protected administrative resources.
	RoleAdmin Role = "admin"
	// RoleUser grants standard authenticated access.
	RoleUser Role = "user"
)

// User is the core domain entity. It never leaves the domain layer with its PasswordHash exposed;
// HTTP handlers must map it to a safe DTO before responding.
type User struct {
	// ID is a UUID v4 string generated at registration time.
	ID string
	// Username is the display name of the user.
	Username string
	// Email is the unique identifier used for login.
	Email string
	// PasswordHash is the bcrypt hash of the user's password. Never serialize this to JSON.
	PasswordHash string
	// Role determines the user's authorization level within the system.
	Role Role
	// IsActive indicates whether the account is enabled.
	IsActive bool
	// CreatedAt is the UTC timestamp of account creation.
	CreatedAt time.Time
	// UpdatedAt is the UTC timestamp of the last modification.
	UpdatedAt time.Time
}

// RegisterRequest is the DTO received by the POST /auth/register endpoint.
type RegisterRequest struct {
	// Username must be non-empty.
	Username string `json:"username"`
	// Email must be non-empty and unique in the system.
	Email string `json:"email"`
	// Password must be at least 8 characters. It is hashed before persistence.
	Password string `json:"password"`
	// Role is optional. Defaults to "user" if omitted.
	Role string `json:"role,omitempty"`
}

// Validate performs field-level validation on RegisterRequest.
// Returns a wrapped ErrValidation on failure.
func (r *RegisterRequest) Validate() error {
	if r.Username == "" {
		return fmt.Errorf("%w: username is required", ErrValidation)
	}
	if r.Email == "" {
		return fmt.Errorf("%w: email is required", ErrValidation)
	}
	if len(r.Password) < 8 {
		return fmt.Errorf("%w: password must be at least 8 characters", ErrValidation)
	}
	return nil
}

// LoginRequest is the DTO received by POST /auth/login.
type LoginRequest struct {
	// Email is the user's registered email address.
	Email string `json:"email"`
	// Password is the plain-text password to compare against the stored hash.
	Password string `json:"password"`
}

// Validate performs field-level validation on LoginRequest.
func (r *LoginRequest) Validate() error {
	if r.Email == "" {
		return fmt.Errorf("%w: email is required", ErrValidation)
	}
	if r.Password == "" {
		return fmt.Errorf("%w: password is required", ErrValidation)
	}
	return nil
}

// UpdateUserRequest is the DTO received by PUT /users/{id}.
// All fields are optional; only non-zero values are applied.
type UpdateUserRequest struct {
	// Username is the new display name. Leave empty to keep the current value.
	Username string `json:"username,omitempty"`
	// Email is the new email address. Leave empty to keep the current value.
	Email string `json:"email,omitempty"`
	// Role is the new role ("admin" | "user"). Leave empty to keep the current value.
	Role string `json:"role,omitempty"`
	// IsActive enables or disables the account. Pointer so we can distinguish false from omitted.
	IsActive *bool `json:"is_active,omitempty"`
}

