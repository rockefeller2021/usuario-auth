// Package repository provides infrastructure adapters for domain.UserRepository.
package repository

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/rockefeller2021/usuario-auth/domain"
)

// MemoryUserRepository is a thread-safe, in-memory implementation of domain.UserRepository.
//
// This adapter is suitable for:
//   - Unit and integration testing
//   - Rapid prototyping before wiring a real database
//
// To use a real database, implement domain.UserRepository in a new adapter
// (e.g., infrastructure/repository/postgres_user_repo.go) and swap it in main.go.
type MemoryUserRepository struct {
	mu      sync.RWMutex
	byID    map[string]*domain.User
	byEmail map[string]*domain.User
}

// NewMemoryUserRepository initializes an empty in-memory repository.
func NewMemoryUserRepository() *MemoryUserRepository {
	return &MemoryUserRepository{
		byID:    make(map[string]*domain.User),
		byEmail: make(map[string]*domain.User),
	}
}

// Save stores the user in both the ID and email indexes.
func (r *MemoryUserRepository) Save(_ context.Context, user *domain.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byID[user.ID] = user
	r.byEmail[user.Email] = user
	return nil
}

// FindByEmail returns the user with the given email or domain.ErrUserNotFound.
func (r *MemoryUserRepository) FindByEmail(_ context.Context, email string) (*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	user, ok := r.byEmail[email]
	if !ok {
		return nil, fmt.Errorf("%w: email=%s", domain.ErrUserNotFound, email)
	}
	return user, nil
}

// FindByID returns the user with the given UUID or domain.ErrUserNotFound.
func (r *MemoryUserRepository) FindByID(_ context.Context, id string) (*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	user, ok := r.byID[id]
	if !ok {
		return nil, fmt.Errorf("%w: id=%s", domain.ErrUserNotFound, id)
	}
	return user, nil
}

// ExistsByEmail returns true if a user with the given email is already stored.
func (r *MemoryUserRepository) ExistsByEmail(_ context.Context, email string) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.byEmail[email]
	return ok, nil
}

// FindAll returns a snapshot of every user currently in the store.
func (r *MemoryUserRepository) FindAll(_ context.Context) ([]*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	users := make([]*domain.User, 0, len(r.byID))
	for _, u := range r.byID {
		users = append(users, u)
	}
	return users, nil
}

// FindByUsername performs a case-insensitive search by username.
// Returns ErrUserNotFound if no match exists.
func (r *MemoryUserRepository) FindByUsername(_ context.Context, username string) (*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	lower := strings.ToLower(username)
	for _, u := range r.byID {
		if strings.ToLower(u.Username) == lower {
			return u, nil
		}
	}
	return nil, fmt.Errorf("%w: username=%s", domain.ErrUserNotFound, username)
}

// Update replaces the stored user with the provided one, keeping both indexes consistent.
// Returns ErrUserNotFound if the user does not exist.
func (r *MemoryUserRepository) Update(_ context.Context, user *domain.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	existing, ok := r.byID[user.ID]
	if !ok {
		return fmt.Errorf("%w: id=%s", domain.ErrUserNotFound, user.ID)
	}
	// Remove old email index entry if the email changed.
	if existing.Email != user.Email {
		delete(r.byEmail, existing.Email)
	}
	r.byID[user.ID] = user
	r.byEmail[user.Email] = user
	return nil
}

// Delete removes the user from both indexes.
// Returns ErrUserNotFound if the user does not exist.
func (r *MemoryUserRepository) Delete(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	existing, ok := r.byID[id]
	if !ok {
		return fmt.Errorf("%w: id=%s", domain.ErrUserNotFound, id)
	}
	delete(r.byID, id)
	delete(r.byEmail, existing.Email)
	return nil
}
