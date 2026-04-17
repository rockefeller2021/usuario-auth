// Package application contains the authentication and user-management use cases.
package application

import (
	"context"
	"fmt"
	"time"

	"github.com/rockefeller2021/usuario-auth/domain"
	"github.com/rockefeller2021/usuario-auth/logger"
)

// UserService orchestrates user-management use cases (listing, search, update, delete).
// It is intentionally separate from AuthService to follow the Single Responsibility Principle.
type UserService struct {
	repo domain.UserRepository
	log  *logger.Logger
}

// NewUserService creates a new UserService with injected dependencies.
func NewUserService(repo domain.UserRepository, log *logger.Logger) *UserService {
	return &UserService{repo: repo, log: log}
}

// ListUsers returns all registered users.
// This operation is intended for admin use only; access control is enforced at the HTTP layer.
func (s *UserService) ListUsers(ctx context.Context) ([]*domain.User, error) {
	s.log.Info("user_service: listing all users")
	users, err := s.repo.FindAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("user_service: listing users: %w", err)
	}
	s.log.Info("user_service: listed users", "count", len(users))
	return users, nil
}

// GetUserByID retrieves a single user profile by their UUID.
func (s *UserService) GetUserByID(ctx context.Context, id string) (*domain.User, error) {
	s.log.Debug("user_service: get by id", "user_id", id)
	user, err := s.repo.FindByID(ctx, id)
	if err != nil {
		s.log.Warn("user_service: user not found by id", "user_id", id)
		return nil, domain.ErrUserNotFound
	}
	return user, nil
}

// GetUserByEmail retrieves a single user profile by their email address.
func (s *UserService) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	s.log.Debug("user_service: get by email", "email", email)
	user, err := s.repo.FindByEmail(ctx, email)
	if err != nil {
		s.log.Warn("user_service: user not found by email", "email", email)
		return nil, domain.ErrUserNotFound
	}
	return user, nil
}

// GetUserByUsername retrieves a single user profile by their username (case-insensitive).
func (s *UserService) GetUserByUsername(ctx context.Context, username string) (*domain.User, error) {
	s.log.Debug("user_service: get by username", "username", username)
	user, err := s.repo.FindByUsername(ctx, username)
	if err != nil {
		s.log.Warn("user_service: user not found by username", "username", username)
		return nil, domain.ErrUserNotFound
	}
	return user, nil
}

// UpdateUser applies the non-zero fields of req to the target user.
//
// Rules:
//   - Only username, email, role and is_active can be changed.
//   - If the requestor is not an admin, they can only update their own account.
//     Role promotion is always an admin-only operation (enforced at HTTP layer).
func (s *UserService) UpdateUser(ctx context.Context, id string, req *domain.UpdateUserRequest) (*domain.User, error) {
	s.log.Info("user_service: update", "user_id", id)

	user, err := s.repo.FindByID(ctx, id)
	if err != nil {
		s.log.Warn("user_service: user not found for update", "user_id", id)
		return nil, domain.ErrUserNotFound
	}

	// Apply only the provided fields (partial update / PATCH semantics).
	if req.Username != "" {
		user.Username = req.Username
	}
	if req.Email != "" {
		user.Email = req.Email
	}
	if req.Role != "" {
		user.Role = domain.Role(req.Role)
	}
	if req.IsActive != nil {
		user.IsActive = *req.IsActive
	}
	user.UpdatedAt = time.Now().UTC()

	if err := s.repo.Update(ctx, user); err != nil {
		return nil, fmt.Errorf("user_service: persisting update: %w", err)
	}

	s.log.Info("user_service: update success", "user_id", id)
	return user, nil
}

// DeleteUser permanently removes a user from the store.
// This operation is intended for admin use only.
func (s *UserService) DeleteUser(ctx context.Context, id string) error {
	s.log.Info("user_service: delete", "user_id", id)
	if err := s.repo.Delete(ctx, id); err != nil {
		s.log.Warn("user_service: user not found for delete", "user_id", id)
		return domain.ErrUserNotFound
	}
	s.log.Info("user_service: deleted", "user_id", id)
	return nil
}
