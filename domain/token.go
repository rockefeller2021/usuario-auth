package domain

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenPair holds an access token and a refresh token issued after a successful login.
// The AccessToken is short-lived; the RefreshToken is used to obtain a new pair.
type TokenPair struct {
	// AccessToken is the short-lived JWT sent as Bearer in Authorization headers.
	AccessToken string `json:"access_token"`
	// RefreshToken is the long-lived JWT used exclusively to renew the access token.
	RefreshToken string `json:"refresh_token"`
	// ExpiresAt is the UTC expiry time of the AccessToken.
	ExpiresAt time.Time `json:"expires_at"`
	// TokenType is always "Bearer".
	TokenType string `json:"token_type"`
}

// Claims is the JWT payload embedded in both access and refresh tokens.
// It extends jwt.RegisteredClaims with application-specific fields.
type Claims struct {
	// UserID is the UUID of the authenticated user.
	UserID string `json:"user_id"`
	// Email is the user's email address at the time of token issuance.
	Email string `json:"email"`
	// Username is the user's display name at the time of token issuance.
	Username string `json:"username"`
	// Role is the user's authorization role at the time of token issuance.
	Role string `json:"role"`

	jwt.RegisteredClaims
}

// RefreshRequest is the DTO received by POST /auth/refresh.
type RefreshRequest struct {
	// RefreshToken is the long-lived token used to obtain a new TokenPair.
	RefreshToken string `json:"refresh_token"`
}
