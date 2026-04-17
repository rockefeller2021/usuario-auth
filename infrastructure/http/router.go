package http

import (
	"net/http"

	"github.com/rockefeller2021/usuario-auth/domain"
	"github.com/rockefeller2021/usuario-auth/logger"
)

// NewRouter builds and returns the complete HTTP handler tree.
//
// Route layout:
//
//	Public (no auth required):
//	  POST /auth/register      → Register
//	  POST /auth/login         → Login
//	  POST /auth/refresh       → Refresh
//	  GET  /health             → Health
//
//	Protected — any authenticated user:
//	  GET  /auth/me            → Me (own profile)
//	  PUT  /users/{id}         → UpdateUser (admin OR own account)
//
//	Protected — admin only:
//	  GET  /users              → ListUsers
//	  GET  /users/search       → SearchUsers (?email= | ?username=)
//	  GET  /users/{id}         → GetUser
//	  DELETE /users/{id}       → DeleteUser
//
// Global middleware chain (outermost → innermost):
//
//	RecoveryMiddleware → LoggerMiddleware → CORSMiddleware → mux
func NewRouter(
	authHandler *AuthHandler,
	userHandler *UserHandler,
	tm domain.TokenManager,
	log *logger.Logger,
	allowedOrigins []string,
) http.Handler {
	mux := http.NewServeMux()

	jwtMW := JWTMiddleware(tm, log)
	adminMW := RequireRole(domain.RoleAdmin)

	// ── Public routes ─────────────────────────────────────────────────────────
	mux.HandleFunc("POST /auth/register", authHandler.Register)
	mux.HandleFunc("POST /auth/login", authHandler.Login)
	mux.HandleFunc("POST /auth/refresh", authHandler.Refresh)
	mux.HandleFunc("GET /health", authHandler.Health)

	// ── Protected — authenticated user ────────────────────────────────────────
	mux.Handle("GET /auth/me", jwtMW(http.HandlerFunc(authHandler.Me)))

	// PUT /users/{id}: JWT required; ownership / role check done inside handler.
	mux.Handle("PUT /users/{id}", jwtMW(http.HandlerFunc(userHandler.UpdateUser)))

	// ── Protected — admin only ────────────────────────────────────────────────
	// NOTE: /users/search must be registered BEFORE /users/{id} so the
	// path "search" is not captured as an {id} wildcard.
	mux.Handle("GET /users/search", jwtMW(adminMW(http.HandlerFunc(userHandler.SearchUsers))))
	mux.Handle("GET /users/{id}", jwtMW(adminMW(http.HandlerFunc(userHandler.GetUser))))
	mux.Handle("GET /users", jwtMW(adminMW(http.HandlerFunc(userHandler.ListUsers))))
	mux.Handle("DELETE /users/{id}", jwtMW(adminMW(http.HandlerFunc(userHandler.DeleteUser))))

	// ── Global middleware chain ────────────────────────────────────────────────
	return RecoveryMiddleware(log)(
		LoggerMiddleware(log)(
			CORSMiddleware(allowedOrigins)(mux),
		),
	)
}
