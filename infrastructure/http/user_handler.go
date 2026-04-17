package http

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/rockefeller2021/usuario-auth/application"
	"github.com/rockefeller2021/usuario-auth/domain"
	"github.com/rockefeller2021/usuario-auth/logger"
)

// UserHandler exposes HTTP endpoints for user management (CRUD).
type UserHandler struct {
	svc *application.UserService
	log *logger.Logger
}

// NewUserHandler creates a new UserHandler.
func NewUserHandler(svc *application.UserService, log *logger.Logger) *UserHandler {
	return &UserHandler{svc: svc, log: log}
}

// safeUser returns a sanitized map safe to expose via JSON (no password hash).
func safeUser(u *domain.User) map[string]any {
	return map[string]any{
		"id":         u.ID,
		"username":   u.Username,
		"email":      u.Email,
		"role":       u.Role,
		"is_active":  u.IsActive,
		"created_at": u.CreatedAt,
		"updated_at": u.UpdatedAt,
	}
}

// ListUsers handles GET /users
// Returns all registered users. Requires admin role.
func (h *UserHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.svc.ListUsers(r.Context())
	if err != nil {
		h.log.Error("handler list_users: service error", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	result := make([]map[string]any, 0, len(users))
	for _, u := range users {
		result = append(result, safeUser(u))
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"users": result,
		"total": len(result),
	})
}

// GetUser handles GET /users/{id}
// Returns a single user by UUID. Requires admin role or ownership.
func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "user id is required")
		return
	}

	user, err := h.svc.GetUserByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			respondError(w, http.StatusNotFound, "user not found")
			return
		}
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	respondJSON(w, http.StatusOK, safeUser(user))
}

// SearchUsers handles GET /users/search
// Supports ?email= and ?username= query params. Requires admin role.
func (h *UserHandler) SearchUsers(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(r.URL.Query().Get("email"))
	username := strings.TrimSpace(r.URL.Query().Get("username"))

	if email == "" && username == "" {
		respondError(w, http.StatusBadRequest, "provide at least one query param: email or username")
		return
	}

	var (
		user *domain.User
		err  error
	)

	switch {
	case email != "":
		user, err = h.svc.GetUserByEmail(r.Context(), email)
	default:
		user, err = h.svc.GetUserByUsername(r.Context(), username)
	}

	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			respondError(w, http.StatusNotFound, "user not found")
			return
		}
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	respondJSON(w, http.StatusOK, safeUser(user))
}

// UpdateUser handles PUT /users/{id}
// Partially updates a user's mutable fields. Requires admin role or ownership.
func (h *UserHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "user id is required")
		return
	}

	// Non-admin users can only update their own account.
	requesterID, _ := r.Context().Value(contextKeyUserID).(string)
	requesterRole, _ := r.Context().Value(contextKeyRole).(string)
	if requesterRole != string(domain.RoleAdmin) && requesterID != id {
		respondError(w, http.StatusForbidden, "forbidden: you can only modify your own account")
		return
	}

	var req domain.UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Non-admins cannot promote roles.
	if requesterRole != string(domain.RoleAdmin) && req.Role != "" {
		respondError(w, http.StatusForbidden, "forbidden: role changes require admin privileges")
		return
	}

	user, err := h.svc.UpdateUser(r.Context(), id, &req)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			respondError(w, http.StatusNotFound, "user not found")
			return
		}
		h.log.Error("handler update_user: service error", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	respondJSON(w, http.StatusOK, safeUser(user))
}

// DeleteUser handles DELETE /users/{id}
// Permanently removes a user. Requires admin role.
func (h *UserHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "user id is required")
		return
	}

	if err := h.svc.DeleteUser(r.Context(), id); err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			respondError(w, http.StatusNotFound, "user not found")
			return
		}
		h.log.Error("handler delete_user: service error", "error", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
