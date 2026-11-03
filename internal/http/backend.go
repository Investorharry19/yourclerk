package http

import (
	"errors"
	nethttp "net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Investorharry19/yourclerk/internal/store"
)

const (
	defaultPageSize = 50
	maxPageSize     = 100
)

type backendUser struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

func toBackendUser(u store.User) backendUser {
	return backendUser{ID: u.ID, Email: u.Email, CreatedAt: u.CreatedAt}
}

func intParam(r *nethttp.Request, name string, def, min, max int) (int, bool) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return def, true
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < min || n > max {
		return 0, false
	}
	return n, true
}

// handleBackendListUsers lists the users of the application the secret key belongs to.
func (s *Server) handleBackendListUsers(w nethttp.ResponseWriter, r *nethttp.Request) {
	limit, ok1 := intParam(r, "limit", defaultPageSize, 1, maxPageSize)
	offset, ok2 := intParam(r, "offset", 0, 0, 1<<30)
	if !ok1 || !ok2 {
		WriteError(w, nethttp.StatusUnprocessableEntity, "validation_error", "limit must be 1-100 and offset a non-negative integer")
		return
	}
	users, err := s.tenant(r).ListUsers(r.Context(), limit, offset)
	if err != nil {
		s.internalError(w, "backend: list users", err)
		return
	}
	out := make([]backendUser, 0, len(users))
	for _, u := range users {
		out = append(out, toBackendUser(u))
	}
	WriteJSON(w, nethttp.StatusOK, map[string]any{"users": out, "limit": limit, "offset": offset})
}

// handleBackendGetUser returns one user. A user of another application is a 404.
func (s *Server) handleBackendGetUser(w nethttp.ResponseWriter, r *nethttp.Request) {
	u, err := s.tenant(r).GetUserByID(r.Context(), chi.URLParam(r, "id"))
	if errors.Is(err, store.ErrNotFound) {
		WriteError(w, nethttp.StatusNotFound, "not_found", "User not found")
		return
	}
	if err != nil {
		s.internalError(w, "backend: get user", err)
		return
	}
	WriteJSON(w, nethttp.StatusOK, toBackendUser(u))
}
