// Package jwt provides an HMAC-SHA256 implementation of domain.TokenManager.
package jwt

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rockefeller2021/usuario-auth/domain"
)

// Config holds the secrets and TTL settings for token generation.
type Config struct {
	// AccessSecret is the HMAC signing key for access tokens. Must be at least 32 bytes.
	AccessSecret string
	// RefreshSecret is the HMAC signing key for refresh tokens. Must be at least 32 bytes.
	RefreshSecret string
	// AccessTokenTTL is the lifetime of the access token. Defaults to 15 minutes.
	AccessTokenTTL time.Duration
	// RefreshTokenTTL is the lifetime of the refresh token. Defaults to 7 days.
	RefreshTokenTTL time.Duration
}

// Manager implements domain.TokenManager using HMAC-SHA256 signed JWTs.
type Manager struct {
	cfg Config
}

// NewManager creates a new Manager. Sensible TTL defaults are applied when zero values are provided.
func NewManager(cfg Config) *Manager {
	if cfg.AccessTokenTTL == 0 {
		cfg.AccessTokenTTL = 15 * time.Minute
	}
	if cfg.RefreshTokenTTL == 0 {
		cfg.RefreshTokenTTL = 7 * 24 * time.Hour
	}
	return &Manager{cfg: cfg}
}

// GeneratePair creates a signed access token and a signed refresh token for the given user.
// The access token embeds full claims; the refresh token only embeds user identity.
func (m *Manager) GeneratePair(user *domain.User) (*domain.TokenPair, error) {
	now := time.Now().UTC()
	accessExp := now.Add(m.cfg.AccessTokenTTL)

	// Access token — full claims
	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, &domain.Claims{
		UserID:   user.ID,
		Email:    user.Email,
		Username: user.Username,
		Role:     string(user.Role),
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.ID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(accessExp),
		},
	}).SignedString([]byte(m.cfg.AccessSecret))
	if err != nil {
		return nil, fmt.Errorf("jwt: signing access token: %w", err)
	}

	// Refresh token — minimal claims (identity only)
	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, &domain.Claims{
		UserID: user.ID,
		Email:  user.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.ID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.cfg.RefreshTokenTTL)),
		},
	}).SignedString([]byte(m.cfg.RefreshSecret))
	if err != nil {
		return nil, fmt.Errorf("jwt: signing refresh token: %w", err)
	}

	return &domain.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    accessExp,
		TokenType:    "Bearer",
	}, nil
}

// ValidateAccessToken parses and validates the given access token string.
// Returns the embedded Claims on success or a wrapped ErrInvalidToken on failure.
func (m *Manager) ValidateAccessToken(tokenStr string) (*domain.Claims, error) {
	return m.parseToken(tokenStr, m.cfg.AccessSecret)
}

// ValidateRefreshToken parses and validates the given refresh token string.
func (m *Manager) ValidateRefreshToken(tokenStr string) (*domain.Claims, error) {
	return m.parseToken(tokenStr, m.cfg.RefreshSecret)
}

// parseToken is the shared parsing logic that validates signing method and expiry.
func (m *Manager) parseToken(tokenStr, secret string) (*domain.Claims, error) {
	claims := &domain.Claims{}

	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("jwt: unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %s", domain.ErrInvalidToken, err.Error())
	}
	if !token.Valid {
		return nil, domain.ErrInvalidToken
	}

	return claims, nil
}
