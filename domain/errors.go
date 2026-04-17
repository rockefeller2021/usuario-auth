// Package domain contains the core business entities and domain errors
// for the usuario-auth library.
package domain

import "errors"

// Sentinel domain errors. Use errors.Is() to check for these.
var (
	// ErrUserNotFound is returned when a user lookup yields no result.
	ErrUserNotFound = errors.New("user not found")

	// ErrUserAlreadyExists is returned when attempting to register with a duplicate email.
	ErrUserAlreadyExists = errors.New("user already exists")

	// ErrInvalidPassword is returned when the provided password does not match the stored hash.
	ErrInvalidPassword = errors.New("invalid password")

	// ErrInvalidToken is returned when a JWT is missing, malformed, or expired.
	ErrInvalidToken = errors.New("invalid or expired token")

	// ErrInactiveUser is returned when a user account has been deactivated.
	ErrInactiveUser = errors.New("user account is inactive")

	// ErrValidation is returned when a request DTO fails field-level validation.
	ErrValidation = errors.New("validation error")
)
