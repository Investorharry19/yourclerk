// Package http wires up the HTTP router, middleware and handlers.
package http

import (
	"context"
	"encoding/json"
	"log/slog"
	nethttp "net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

// Pinger is anything that can check database connectivity.
// *store.Store satisfies it; tests can use a fake.
type Pinger interface {
	Ping(ctx context.Context) error
}

type Server struct {
	log      *slog.Logger
	db       Pinger
	users    UserStore
	sessions SessionStore
	opts     Options
}

func NewServer(log *slog.Logger, db Pinger, users UserStore, sessions SessionStore, opts Options) *Server {
	return &Server{log: log, db: db, users: users, sessions: sessions, opts: opts.withDefaults()}
}

// Handler builds the router with all middleware applied.
func (s *Server) Handler() nethttp.Handler {
	r := chi.NewRouter()
	r.Use(RequestID)
	r.Use(Logger(s.log))
	r.Use(Recoverer(s.log))

	r.Get("/healthz", s.handleHealthz)
	r.Get("/.well-known/jwks.json", s.handleJWKS)
	if s.opts.EnableDocs {
		r.Get("/docs", s.handleDocs)
		r.Get("/openapi.json", s.handleOpenAPI)
	}

	r.Route("/v1", func(r chi.Router) {
		r.Post("/signup", s.handleSignup)
		r.Post("/login", s.handleLogin)

		r.Group(func(r chi.Router) {
			r.Use(s.requireAuth)
			r.Get("/me", s.handleMe)
			r.Post("/logout", s.handleLogout)
			r.Get("/sessions", s.handleListSessions)
			r.Delete("/sessions/{id}", s.handleRevokeSession)
			r.Post("/sessions/{id}/token", s.handleIssueToken)
		})
	})
	return r
}

func (s *Server) handleHealthz(w nethttp.ResponseWriter, r *nethttp.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	if err := s.db.Ping(ctx); err != nil {
		s.log.Error("healthz: database ping failed", "err", err)
		WriteJSON(w, nethttp.StatusServiceUnavailable, map[string]string{"status": "unavailable", "database": "down"})
		return
	}
	WriteJSON(w, nethttp.StatusOK, map[string]string{"status": "ok", "database": "up"})
}

// WriteJSON writes v as a JSON response with the given status.
func WriteJSON(w nethttp.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type errorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// WriteError writes the consistent JSON error shape used by every endpoint.
func WriteError(w nethttp.ResponseWriter, status int, code, message string) {
	var b errorBody
	b.Error.Code = code
	b.Error.Message = message
	WriteJSON(w, status, b)
}
