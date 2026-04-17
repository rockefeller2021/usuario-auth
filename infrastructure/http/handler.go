// Package http provides the HTTP layer for the usuario-auth library.
// It wires HTTP handlers, middleware, and routing using only net/http from the standard library.
package http

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/rockefeller2021/usuario-auth/application"
	"github.com/rockefeller2021/usuario-auth/domain"
	"github.com/rockefeller2021/usuario-auth/logger"
)

// AuthHandler holds the HTTP handlers for all authentication endpoints.
type AuthHandler struct {
	svc *application.AuthService
	log *logger.Logger
}

// NewAuthHandler creates a new AuthHandler with the given service and logger.
func NewAuthHandler(svc *application.AuthService, log *logger.Logger) *AuthHandler {
	return &AuthHandler{svc: svc, log: log}
}

// Register handles POST /auth/register
// Creates a new user account and returns a sanitized user profile.
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req domain.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.log.Warn("handler register: failed to decode body", "error", err)
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	user, err := h.svc.Register(r.Context(), &req)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	respondJSON(w, http.StatusCreated, map[string]any{
		"id":         user.ID,
		"username":   user.Username,
		"email":      user.Email,
		"role":       user.Role,
		"created_at": user.CreatedAt,
	})
}

// Login handles POST /auth/login
// Validates credentials and returns a TokenPair on success.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req domain.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.log.Warn("handler login: failed to decode body", "error", err)
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	pair, err := h.svc.Login(r.Context(), &req)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, pair)
}

// Refresh handles POST /auth/refresh
// Validates a refresh token and issues a new TokenPair.
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req domain.RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.log.Warn("handler refresh: failed to decode body", "error", err)
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	pair, err := h.svc.RefreshToken(r.Context(), &req)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, pair)
}

// Me handles GET /auth/me (protected)
// Returns the profile of the currently authenticated user.
// Requires a valid Bearer token; the user ID is injected by JWTMiddleware.
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(contextKeyUserID).(string)
	if !ok || userID == "" {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	user, err := h.svc.GetProfile(r.Context(), userID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"id":         user.ID,
		"username":   user.Username,
		"email":      user.Email,
		"role":       user.Role,
		"is_active":  user.IsActive,
		"created_at": user.CreatedAt,
	})
}

// Health handles GET /health
// Returns a simple status check for load balancer probes.
func (h *AuthHandler) Health(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleServiceError maps domain errors to the appropriate HTTP status codes.
// Unknown errors are logged and mapped to 500 Internal Server Error.
func (h *AuthHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domain.ErrUserNotFound):
		respondError(w, http.StatusNotFound, "user not found")
	case errors.Is(err, domain.ErrUserAlreadyExists):
		respondError(w, http.StatusConflict, "email already registered")
	case errors.Is(err, domain.ErrInvalidPassword):
		respondError(w, http.StatusUnauthorized, "invalid credentials")
	case errors.Is(err, domain.ErrInvalidToken):
		respondError(w, http.StatusUnauthorized, "invalid or expired token")
	case errors.Is(err, domain.ErrInactiveUser):
		respondError(w, http.StatusForbidden, "account is inactive")
	case errors.Is(err, domain.ErrValidation):
		respondError(w, http.StatusBadRequest, err.Error())
	default:
		h.log.Error("handler: unexpected service error", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
	}
}

// respondJSON serializes body to JSON and writes it with the given status code.
func respondJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// respondError writes a standardized {"error": "<message>"} JSON response.
func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, map[string]string{"error": message})
}
