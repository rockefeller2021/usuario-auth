package application

import (
	"context"
	"testing"
	"time"

	"github.com/rockefeller2021/usuario-auth/domain"
	"github.com/rockefeller2021/usuario-auth/logger"
)

// ─── Mock: UserRepository ────────────────────────────────────────────────────

type mockUserRepo struct {
	users map[string]*domain.User
}

func newMockRepo() *mockUserRepo {
	return &mockUserRepo{users: make(map[string]*domain.User)}
}

func (m *mockUserRepo) Save(_ context.Context, u *domain.User) error {
	m.users[u.Email] = u
	return nil
}
func (m *mockUserRepo) FindByEmail(_ context.Context, email string) (*domain.User, error) {
	u, ok := m.users[email]
	if !ok {
		return nil, domain.ErrUserNotFound
	}
	return u, nil
}
func (m *mockUserRepo) FindByID(_ context.Context, id string) (*domain.User, error) {
	for _, u := range m.users {
		if u.ID == id {
			return u, nil
		}
	}
	return nil, domain.ErrUserNotFound
}
func (m *mockUserRepo) ExistsByEmail(_ context.Context, email string) (bool, error) {
	_, ok := m.users[email]
	return ok, nil
}
func (m *mockUserRepo) FindAll(_ context.Context) ([]*domain.User, error) {
	users := make([]*domain.User, 0, len(m.users))
	for _, u := range m.users {
		users = append(users, u)
	}
	return users, nil
}
func (m *mockUserRepo) FindByUsername(_ context.Context, username string) (*domain.User, error) {
	for _, u := range m.users {
		if u.Username == username {
			return u, nil
		}
	}
	return nil, domain.ErrUserNotFound
}
func (m *mockUserRepo) Update(_ context.Context, user *domain.User) error {
	if _, ok := m.users[user.Email]; !ok {
		return domain.ErrUserNotFound
	}
	m.users[user.Email] = user
	return nil
}
func (m *mockUserRepo) Delete(_ context.Context, id string) error {
	for email, u := range m.users {
		if u.ID == id {
			delete(m.users, email)
			return nil
		}
	}
	return domain.ErrUserNotFound
}


// ─── Mock: TokenManager ──────────────────────────────────────────────────────

type mockTokenManager struct{}

func (m *mockTokenManager) GeneratePair(user *domain.User) (*domain.TokenPair, error) {
	return &domain.TokenPair{
		AccessToken:  "mock-access-" + user.ID,
		RefreshToken: "mock-refresh-" + user.ID,
		ExpiresAt:    time.Now().Add(15 * time.Minute),
		TokenType:    "Bearer",
	}, nil
}
func (m *mockTokenManager) ValidateAccessToken(token string) (*domain.Claims, error) {
	return &domain.Claims{UserID: "test-id"}, nil
}
func (m *mockTokenManager) ValidateRefreshToken(token string) (*domain.Claims, error) {
	return &domain.Claims{UserID: "test-id"}, nil
}

// ─── Test helpers ────────────────────────────────────────────────────────────

func newTestService() *AuthService {
	return NewAuthService(newMockRepo(), &mockTokenManager{}, logger.Default())
}

// ─── Tests ───────────────────────────────────────────────────────────────────

func TestRegister_Success(t *testing.T) {
	svc := newTestService()
	user, err := svc.Register(context.Background(), &domain.RegisterRequest{
		Username: "alice",
		Email:    "alice@example.com",
		Password: "securepassword",
	})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if user.Email != "alice@example.com" {
		t.Errorf("expected email alice@example.com, got %s", user.Email)
	}
	if user.Role != domain.RoleUser {
		t.Errorf("expected role %s, got %s", domain.RoleUser, user.Role)
	}
}

func TestRegister_DuplicateEmail(t *testing.T) {
	svc := newTestService()
	req := &domain.RegisterRequest{Username: "alice", Email: "dup@example.com", Password: "password123"}
	_, _ = svc.Register(context.Background(), req)

	_, err := svc.Register(context.Background(), req)
	if err != domain.ErrUserAlreadyExists {
		t.Errorf("expected ErrUserAlreadyExists, got: %v", err)
	}
}

func TestRegister_ValidationError_ShortPassword(t *testing.T) {
	svc := newTestService()
	_, err := svc.Register(context.Background(), &domain.RegisterRequest{
		Username: "bob",
		Email:    "bob@example.com",
		Password: "123",
	})
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
}

func TestLogin_Success(t *testing.T) {
	svc := newTestService()
	_, _ = svc.Register(context.Background(), &domain.RegisterRequest{
		Username: "charlie",
		Email:    "charlie@example.com",
		Password: "mypassword",
	})

	pair, err := svc.Login(context.Background(), &domain.LoginRequest{
		Email:    "charlie@example.com",
		Password: "mypassword",
	})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if pair.AccessToken == "" {
		t.Error("expected a non-empty access token")
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	svc := newTestService()
	_, _ = svc.Register(context.Background(), &domain.RegisterRequest{
		Username: "dana",
		Email:    "dana@example.com",
		Password: "correctpass",
	})

	_, err := svc.Login(context.Background(), &domain.LoginRequest{
		Email:    "dana@example.com",
		Password: "wrongpass",
	})
	if err != domain.ErrInvalidPassword {
		t.Errorf("expected ErrInvalidPassword, got: %v", err)
	}
}

func TestLogin_UserNotFound(t *testing.T) {
	svc := newTestService()
	_, err := svc.Login(context.Background(), &domain.LoginRequest{
		Email:    "ghost@example.com",
		Password: "anything",
	})
	if err != domain.ErrUserNotFound {
		t.Errorf("expected ErrUserNotFound, got: %v", err)
	}
}
