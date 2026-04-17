# 🔐 usuario-auth

> JWT Authentication Library for Go — Hexagonal Architecture, stdlib only.

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A production-ready, reusable JWT authentication library written in pure Go.
No frameworks — only `net/http`, [`golang-jwt/jwt/v5`](https://github.com/golang-jwt/jwt), [`google/uuid`](https://github.com/google/uuid), and [`golang.org/x/crypto`](https://pkg.go.dev/golang.org/x/crypto).

---

## Features

- ✅ **Register / Login / Refresh / Profile** endpoints
- ✅ **Access + Refresh token pair** (HMAC-SHA256, separate secrets)
- ✅ **Hexagonal Architecture** — swap DB/tokens without touching business logic
- ✅ **Structured logging** via `log/slog` (JSON in prod, text in dev)
- ✅ **Middleware pipeline**: Logger · Recovery · CORS · JWT
- ✅ **Graceful shutdown** with configurable drain timeout
- ✅ **ASCII banner** on server start
- ✅ **Thread-safe in-memory repository** (plug your own: Postgres, MongoDB…)
- ✅ **Unit tests** with mock adapters (no real DB or JWT needed)

---

## Project Structure

```
usuario-auth/
├── domain/                     # Entities, DTOs, Ports (interfaces), domain errors
│   ├── errors.go
│   ├── ports.go                # UserRepository + TokenManager interfaces
│   ├── token.go                # TokenPair, Claims, RefreshRequest
│   └── user.go                 # User entity, RegisterRequest, LoginRequest
│
├── application/                # Use cases
│   ├── auth_service.go         # Register, Login, RefreshToken, GetProfile
│   └── auth_service_test.go    # Unit tests with mocks
│
├── infrastructure/
│   ├── jwt/
│   │   └── jwt_manager.go      # domain.TokenManager → HMAC-SHA256
│   ├── repository/
│   │   └── memory_user_repo.go # domain.UserRepository → thread-safe in-memory
│   └── http/
│       ├── handler.go          # HTTP Handlers
│       ├── middleware.go       # Logger, Recovery, CORS, JWT
│       └── router.go          # net/http ServeMux wiring
│
├── server/
│   └── server.go               # Banner, graceful shutdown, config
│
├── logger/
│   └── logger.go               # log/slog wrapper (JSON / text)
│
└── cmd/
    └── main.go                 # Demo entry point
```

---

## Quick Start (run the demo)

```bash
git clone https://github.com/rockefeller2021/usuario-auth.git
cd usuario-auth

# Optional: copy and edit environment variables
cp .env.example .env

go run ./cmd/main.go
```

On startup you will see:

```
╔══════════════════════════════════════════════════════════════╗
║   ██╗   ██╗███████╗██╗   ██╗ █████╗ ██████╗ ██╗ ██████╗    ║
║   ...                                                        ║
║          🔐  JWT Auth Library  ·  v1.0.0                     ║
╚══════════════════════════════════════════════════════════════╝

time=... level=INFO msg="server initializing" addr=:8080 pid=12345
time=... level=INFO msg="🚀 Server listening → http://localhost:8080"
```

---

## API Reference

| Method | Route | Auth | Description |
|--------|-------|------|-------------|
| `POST` | `/auth/register` | ❌ | Create a new account |
| `POST` | `/auth/login` | ❌ | Login, returns TokenPair |
| `POST` | `/auth/refresh` | ❌ | Renew access token |
| `GET`  | `/auth/me` | ✅ Bearer | Authenticated user profile |
| `GET`  | `/health` | ❌ | Health check |

### POST /auth/register
```json
{ "username": "alice", "email": "alice@example.com", "password": "mypassword" }
```

### POST /auth/login
```json
{ "email": "alice@example.com", "password": "mypassword" }
```
Response:
```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "expires_at": "2026-04-16T12:00:00Z",
  "token_type": "Bearer"
}
```

### POST /auth/refresh
```json
{ "refresh_token": "eyJ..." }
```

### GET /auth/me
```
Authorization: Bearer eyJ...
```

---

## Use as a Package

```go
import (
    "github.com/rockefeller2021/usuario-auth/application"
    "github.com/rockefeller2021/usuario-auth/infrastructure/jwt"
    "github.com/rockefeller2021/usuario-auth/infrastructure/repository"
    "github.com/rockefeller2021/usuario-auth/logger"
)

log := logger.New(logger.Config{Level: logger.LevelInfo, Format: "json"})

jwtMgr := jwt.NewManager(jwt.Config{
    AccessSecret:  os.Getenv("JWT_ACCESS_SECRET"),
    RefreshSecret: os.Getenv("JWT_REFRESH_SECRET"),
})

// Swap with your own domain.UserRepository implementation:
repo := repository.NewMemoryUserRepository()

svc := application.NewAuthService(repo, jwtMgr, log)
```

### Implementing your own UserRepository (e.g., PostgreSQL)

```go
type PostgresUserRepo struct { db *sql.DB }

func (r *PostgresUserRepo) Save(ctx context.Context, u *domain.User) error { ... }
func (r *PostgresUserRepo) FindByEmail(ctx context.Context, email string) (*domain.User, error) { ... }
func (r *PostgresUserRepo) FindByID(ctx context.Context, id string) (*domain.User, error) { ... }
func (r *PostgresUserRepo) ExistsByEmail(ctx context.Context, email string) (bool, error) { ... }
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | HTTP listen port |
| `ENV` | `development` | `production` enables JSON logs |
| `JWT_ACCESS_SECRET` | *(unsafe default)* | HMAC key for access tokens (min 32 bytes) |
| `JWT_REFRESH_SECRET` | *(unsafe default)* | HMAC key for refresh tokens (min 32 bytes) |

> **Generate secrets:** `openssl rand -hex 32`

---

## Running Tests

```bash
go test ./... -v
```

---

## License

MIT © 2026 rockefeller2021
