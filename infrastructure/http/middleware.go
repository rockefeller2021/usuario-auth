package http

import (
	"context"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/rockefeller2021/usuario-auth/domain"
	"github.com/rockefeller2021/usuario-auth/logger"
)

// contextKey is a private type for context value keys to avoid collisions.
type contextKey string

const (
	// contextKeyUserID is the key used to store the authenticated user's ID in the request context.
	contextKeyUserID contextKey = "user_id"
	// contextKeyRole is the key used to store the authenticated user's role in the request context.
	contextKeyRole contextKey = "role"
)

// ─── LoggerMiddleware ─────────────────────────────────────────────────────────

// LoggerMiddleware logs every HTTP request with method, path, status code, and duration.
// Output goes through the shared logger, using structured fields for easy log aggregation.
func LoggerMiddleware(log *logger.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}

			next.ServeHTTP(rw, r)

			log.Info("http request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rw.status,
				"duration_ms", time.Since(start).Milliseconds(),
				"remote_addr", r.RemoteAddr,
				"user_agent", r.UserAgent(),
			)
		})
	}
}

// ─── RecoveryMiddleware ───────────────────────────────────────────────────────

// RecoveryMiddleware catches any panics in downstream handlers, logs the full stack trace,
// and returns a 500 Internal Server Error to the client without crashing the server.
func RecoveryMiddleware(log *logger.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					log.Error("panic recovered",
						"panic", rec,
						"method", r.Method,
						"path", r.URL.Path,
						"stack", string(debug.Stack()),
					)
					respondError(w, http.StatusInternalServerError, "internal server error")
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// ─── CORSMiddleware ───────────────────────────────────────────────────────────

// CORSMiddleware adds CORS headers to all responses.
// Pass []string{"*"} to allow all origins, or a specific list (e.g., ["https://myapp.com"]).
func CORSMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			for _, o := range allowedOrigins {
				if o == "*" || o == origin {
					w.Header().Set("Access-Control-Allow-Origin", o)
					break
				}
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

			// Handle preflight requests
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ─── JWTMiddleware ────────────────────────────────────────────────────────────

// JWTMiddleware validates the Bearer token from the Authorization header.
// On success, it injects the user ID and role into the request context.
// On failure, it short-circuits with 401 Unauthorized.
func JWTMiddleware(tm domain.TokenManager, log *logger.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
				log.Warn("jwt middleware: missing or malformed authorization header",
					"method", r.Method, "path", r.URL.Path)
				respondError(w, http.StatusUnauthorized, "missing or invalid authorization header")
				return
			}

			tokenStr := strings.TrimPrefix(auth, "Bearer ")
			claims, err := tm.ValidateAccessToken(tokenStr)
			if err != nil {
				log.Warn("jwt middleware: token validation failed",
					"error", err, "path", r.URL.Path)
				respondError(w, http.StatusUnauthorized, "invalid or expired token")
				return
			}

			// Inject claims into context for downstream handlers
			ctx := context.WithValue(r.Context(), contextKeyUserID, claims.UserID)
			ctx = context.WithValue(ctx, contextKeyRole, claims.Role)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ─── responseWriter ───────────────────────────────────────────────────────────

// responseWriter wraps http.ResponseWriter to capture the HTTP status code
// after it has been written, enabling accurate request logging.
type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// ─── RequireRole ──────────────────────────────────────────────────────────────

// RequireRole short-circuits with 403 Forbidden if the authenticated user's role
// is not in the allowed list. Must be placed after JWTMiddleware in the chain
// so that contextKeyRole is already populated.
func RequireRole(allowed ...domain.Role) func(http.Handler) http.Handler {
	permitted := make(map[string]struct{}, len(allowed))
	for _, r := range allowed {
		permitted[string(r)] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role, _ := r.Context().Value(contextKeyRole).(string)
			if _, ok := permitted[role]; !ok {
				respondError(w, http.StatusForbidden, "forbidden: insufficient permissions")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

