// Package http wires up the HTTP router, middleware and handlers.
package http

import (
	"context"
	"encoding/json"
	"log/slog"
	nethttp "net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Investorharry19/yourclerk/internal/auth"
	"github.com/Investorharry19/yourclerk/internal/store"
)

// Pinger is anything that can check database connectivity.
// *store.Store satisfies it; tests can use a fake.
type Pinger interface {
	Ping(ctx context.Context) error
}

// TenantProvider hands out the data handle of one application.
// *store.Store satisfies it; tests use an in-memory fake.
type TenantProvider interface {
	ForApp(appID string) store.Tenant
}

// TokenIssuer mints access tokens, rotates keys and publishes the public keys,
// separately for each application. *auth.TokenService satisfies it.
type TokenIssuer interface {
	Issue(ctx context.Context, appID, userID, sessionID string, now time.Time) (token string, expiresAt time.Time, err error)
	JWKS(ctx context.Context, appID string, now time.Time) (auth.JWKS, error)
	EnsureKey(ctx context.Context, appID string, now time.Time) error
	Rotate(ctx context.Context, appID string, now time.Time, delay time.Duration) (kid string, activeFrom time.Time, err error)
	Issuer(appID string) string
	JWKSURL(appID string) string
}

// Deps is everything the server needs. The store satisfies every interface in it.
type Deps struct {
	Log        *slog.Logger
	DB         Pinger
	Registry   store.AppRegistry   // resolves an application from the credential a request carries
	Developers store.Developers    // dashboard accounts
	Apps       store.DeveloperApps // a developer's applications
	Tenants    TenantProvider      // per-application users and sessions
	Tokens     TokenIssuer         // per-application access tokens and JWKS
	Options    Options
}

type Server struct {
	log        *slog.Logger
	db         Pinger
	registry   store.AppRegistry
	developers store.Developers
	apps       store.DeveloperApps
	tenants    TenantProvider
	tokens     TokenIssuer
	opts       Options
}

func NewServer(d Deps) *Server {
	return &Server{
		log: d.Log, db: d.DB, registry: d.Registry, developers: d.Developers,
		apps: d.Apps, tenants: d.Tenants, tokens: d.Tokens, opts: d.Options.withDefaults(),
	}
}

// Handler builds the router with all middleware applied.
//
// Three audiences, three credentials:
//
//	/v1/...           end users of an application   X-Publishable-Key header + session cookie
//	/v1/backend/...   a developer's server          Authorization: Bearer sk_live_...
//	/v1/platform/...  a developer in the dashboard  Authorization: Bearer dvt_...
func (s *Server) Handler() nethttp.Handler {
	r := chi.NewRouter()
	r.Use(RequestID)
	r.Use(Logger(s.log))
	r.Use(Recoverer(s.log))

	r.Get("/healthz", s.handleHealthz)
	r.Get("/apps/{app_id}/.well-known/jwks.json", s.handleJWKS)
	if s.opts.EnableDocs {
		r.Get("/docs", s.handleDocs)
		r.Get("/openapi.json", s.handleOpenAPI)
	}

	r.Route("/v1", func(r chi.Router) {
		// End users: the publishable key picks the application.
		r.Group(func(r chi.Router) {
			r.Use(s.resolveApplication)
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

		// A developer's backend: the secret key picks the application.
		r.Route("/backend", func(r chi.Router) {
			r.Use(s.requireSecretKey)
			r.Get("/users", s.handleBackendListUsers)
			r.Get("/users/{id}", s.handleBackendGetUser)
		})

		// The dashboard API: a developer signs in and manages their applications.
		r.Route("/platform", func(r chi.Router) {
			r.Post("/signup", s.handlePlatformSignup)
			r.Post("/login", s.handlePlatformLogin)

			r.Group(func(r chi.Router) {
				r.Use(s.requireDeveloper)
				r.Get("/me", s.handlePlatformMe)
				r.Post("/logout", s.handlePlatformLogout)
				r.Get("/applications", s.handleListApplications)
				r.Post("/applications", s.handleCreateApplication)
				r.Get("/applications/{id}", s.handleGetApplication)
				r.Patch("/applications/{id}", s.handleUpdateApplication)
				r.Post("/applications/{id}/secret-key/roll", s.handleRollSecretKey)
				r.Post("/applications/{id}/signing-keys/rotate", s.handleRotateSigningKey)
			})
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
