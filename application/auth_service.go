// Package application contains the authentication use cases.
// It depends only on domain interfaces (ports), making it fully testable
// by injecting mock implementations of UserRepository and TokenManager.
package application

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rockefeller2021/usuario-auth/domain"
	"github.com/rockefeller2021/usuario-auth/logger"
	"golang.org/x/crypto/bcrypt"
)

// AuthService orchestrates all authentication use cases.
// It is the single entry point for the application layer.
type AuthService struct {
	repo   domain.UserRepository
	tokens domain.TokenManager
	log    *logger.Logger
}

// NewAuthService creates a new AuthService with injected dependencies.
// All dependencies are expressed as interfaces, enabling easy mocking in tests.
func NewAuthService(
	repo domain.UserRepository,
	tokens domain.TokenManager,
	log *logger.Logger,
) *AuthService {
	return &AuthService{repo: repo, tokens: tokens, log: log}
}

// Register creates a new user account.
//
// Steps:
//  1. Validate request fields.
//  2. Check email uniqueness.
//  3. Hash password with bcrypt.
//  4. Persist the new User entity.
func (s *AuthService) Register(ctx context.Context, req *domain.RegisterRequest) (*domain.User, error) {
	s.log.Info("register: starting", "email", req.Email, "username", req.Username)

	if err := req.Validate(); err != nil {
		s.log.Warn("register: validation failed", "error", err)
		return nil, err
	}

	exists, err := s.repo.ExistsByEmail(ctx, req.Email)
	if err != nil {
		return nil, fmt.Errorf("register: checking email existence: %w", err)
	}
	if exists {
		s.log.Warn("register: email already registered", "email", req.Email)
		return nil, domain.ErrUserAlreadyExists
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("register: hashing password: %w", err)
	}

	role := domain.RoleUser
	if req.Role != "" {
		role = domain.Role(req.Role)
	}

	now := time.Now().UTC()
	user := &domain.User{
		ID:           uuid.NewString(),
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: string(hash),
		Role:         role,
		IsActive:     true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.repo.Save(ctx, user); err != nil {
		return nil, fmt.Errorf("register: persisting user: %w", err)
	}

	s.log.Info("register: success", "user_id", user.ID, "email", user.Email, "role", user.Role)
	return user, nil
}

// Login validates credentials and returns a TokenPair on success.
//
// Steps:
//  1. Validate request fields.
//  2. Fetch user by email.
//  3. Verify password against bcrypt hash.
//  4. Generate and return a new TokenPair.
func (s *AuthService) Login(ctx context.Context, req *domain.LoginRequest) (*domain.TokenPair, error) {
	s.log.Info("login: attempt", "email", req.Email)

	if err := req.Validate(); err != nil {
		s.log.Warn("login: validation failed", "error", err)
		return nil, err
	}

	user, err := s.repo.FindByEmail(ctx, req.Email)
	if err != nil {
		s.log.Warn("login: user not found", "email", req.Email)
		return nil, domain.ErrUserNotFound
	}

	if !user.IsActive {
		s.log.Warn("login: inactive account", "email", req.Email, "user_id", user.ID)
		return nil, domain.ErrInactiveUser
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		s.log.Warn("login: invalid password", "email", req.Email)
		return nil, domain.ErrInvalidPassword
	}

	pair, err := s.tokens.GeneratePair(user)
	if err != nil {
		return nil, fmt.Errorf("login: generating token pair: %w", err)
	}

	s.log.Info("login: success", "user_id", user.ID, "email", user.Email, "role", user.Role)
	return pair, nil
}

// RefreshToken validates a refresh token and issues a new TokenPair.
//
// Steps:
//  1. Validate and parse the refresh token.
//  2. Look up the user to ensure they still exist and are active.
//  3. Generate and return a new TokenPair.
func (s *AuthService) RefreshToken(ctx context.Context, req *domain.RefreshRequest) (*domain.TokenPair, error) {
	s.log.Info("refresh: token renewal attempt")

	claims, err := s.tokens.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		s.log.Warn("refresh: invalid refresh token", "error", err)
		return nil, domain.ErrInvalidToken
	}

	user, err := s.repo.FindByID(ctx, claims.UserID)
	if err != nil {
		s.log.Warn("refresh: user not found", "user_id", claims.UserID)
		return nil, domain.ErrUserNotFound
	}

	if !user.IsActive {
		s.log.Warn("refresh: inactive account", "user_id", user.ID)
		return nil, domain.ErrInactiveUser
	}

	pair, err := s.tokens.GeneratePair(user)
	if err != nil {
		return nil, fmt.Errorf("refresh: generating token pair: %w", err)
	}

	s.log.Info("refresh: success", "user_id", user.ID)
	return pair, nil
}

// GetProfile retrieves the public profile of an authenticated user by their UUID.
func (s *AuthService) GetProfile(ctx context.Context, userID string) (*domain.User, error) {
	s.log.Debug("profile: fetching", "user_id", userID)

	user, err := s.repo.FindByID(ctx, userID)
	if err != nil {
		s.log.Warn("profile: user not found", "user_id", userID)
		return nil, domain.ErrUserNotFound
	}

	return user, nil
}
