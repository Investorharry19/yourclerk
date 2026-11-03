package http

import (
	"context"
	"errors"
	nethttp "net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"github.com/Investorharry19/yourclerk/internal/auth"
	"github.com/Investorharry19/yourclerk/internal/password"
	"github.com/Investorharry19/yourclerk/internal/store"
)

// Bounds for per-application settings. They match the CHECK constraints in the
// database; the API gives friendly errors, the database is the backstop.
const (
	minSessionLifetime = time.Hour
	maxSessionLifetime = 365 * 24 * time.Hour
	minIdleTimeout     = 5 * time.Minute
	maxAppNameLen      = 100
	maxAllowedOrigins  = 20
)

// --- developer auth ---------------------------------------------------------

func (s *Server) requireDeveloper(next nethttp.Handler) nethttp.Handler {
	return nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		tok := bearer(r)
		if !auth.IsDeveloperToken(tok) {
			writeUnauthorized(w)
			return
		}
		dev, err := s.developers.GetLiveDeveloperSession(r.Context(), auth.HashToken(tok), s.opts.Now())
		if errors.Is(err, store.ErrNotFound) {
			writeUnauthorized(w)
			return
		}
		if err != nil {
			s.internalError(w, "developer auth", err)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), developerCtxKey, dev)))
	})
}

func developerFrom(r *nethttp.Request) store.Developer {
	d, _ := r.Context().Value(developerCtxKey).(store.Developer)
	return d
}

type developerResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

func (s *Server) handlePlatformSignup(w nethttp.ResponseWriter, r *nethttp.Request) {
	var in credentials
	if !decodeJSON(w, r, &in) {
		return
	}
	email, ok := normalizeEmail(in.Email)
	if !ok {
		WriteError(w, nethttp.StatusUnprocessableEntity, "validation_error", "Enter a valid email address")
		return
	}
	if msg := validatePassword(in.Password); msg != "" {
		WriteError(w, nethttp.StatusUnprocessableEntity, "validation_error", msg)
		return
	}
	hash, err := password.Hash(in.Password)
	if err != nil {
		s.internalError(w, "platform signup: hash", err)
		return
	}
	dev, err := s.developers.CreateDeveloper(r.Context(), email, hash)
	if errors.Is(err, store.ErrEmailTaken) {
		WriteError(w, nethttp.StatusConflict, "email_taken", "An account with this email already exists")
		return
	}
	if err != nil {
		s.internalError(w, "platform signup: create", err)
		return
	}
	WriteJSON(w, nethttp.StatusCreated, developerResponse{ID: dev.ID, Email: dev.Email})
}

func (s *Server) handlePlatformLogin(w nethttp.ResponseWriter, r *nethttp.Request) {
	var in credentials
	if !decodeJSON(w, r, &in) {
		return
	}
	var (
		dev   store.Developer
		found bool
	)
	if email, ok := normalizeEmail(in.Email); ok {
		d, err := s.developers.GetDeveloperByEmail(r.Context(), email)
		switch {
		case err == nil:
			dev, found = d, true
		case errors.Is(err, store.ErrNotFound):
		default:
			s.internalError(w, "platform login: get developer", err)
			return
		}
	}
	if !found {
		password.DummyVerify(in.Password)
		writeInvalidCredentials(w)
		return
	}
	match, err := password.Verify(in.Password, dev.PasswordHash)
	if err != nil {
		// Includes the legacy placeholder account, whose hash is not a valid
		// encoding: nobody can sign in as it.
		password.DummyVerify(in.Password)
		writeInvalidCredentials(w)
		return
	}
	if !match {
		writeInvalidCredentials(w)
		return
	}

	token, hash, err := auth.NewDeveloperToken()
	if err != nil {
		s.internalError(w, "platform login: token", err)
		return
	}
	now := s.opts.Now()
	exp := now.Add(auth.DeveloperSessionTTL)
	if err := s.developers.CreateDeveloperSession(r.Context(), dev.ID, hash, now, exp); err != nil {
		s.internalError(w, "platform login: session", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	WriteJSON(w, nethttp.StatusOK, map[string]any{
		"token":      token,
		"token_type": "Bearer",
		"expires_at": exp,
		"developer":  developerResponse{ID: dev.ID, Email: dev.Email},
	})
}

func (s *Server) handlePlatformMe(w nethttp.ResponseWriter, r *nethttp.Request) {
	d := developerFrom(r)
	WriteJSON(w, nethttp.StatusOK, developerResponse{ID: d.ID, Email: d.Email})
}

func (s *Server) handlePlatformLogout(w nethttp.ResponseWriter, r *nethttp.Request) {
	if err := s.developers.RevokeDeveloperSession(r.Context(), auth.HashToken(bearer(r)), s.opts.Now()); err != nil {
		s.internalError(w, "platform logout", err)
		return
	}
	w.WriteHeader(nethttp.StatusNoContent)
}

// --- applications -----------------------------------------------------------

type settingsResponse struct {
	AllowedOrigins     []string `json:"allowed_origins"`
	SessionLifetimeSec int      `json:"session_lifetime_seconds"`
	SessionIdleTimeout int      `json:"session_idle_timeout_seconds"`
	SignupEnabled      bool     `json:"signup_enabled"`
}

type applicationResponse struct {
	ID             string           `json:"id"`
	Name           string           `json:"name"`
	PublishableKey string           `json:"publishable_key"`
	SecretKeyLast4 string           `json:"secret_key_last4"`
	Issuer         string           `json:"issuer"`
	JWKSURL        string           `json:"jwks_url"`
	Settings       settingsResponse `json:"settings"`
	CreatedAt      time.Time        `json:"created_at"`
	// SecretKey is present only in the response that creates or rolls it.
	// It cannot be retrieved afterwards.
	SecretKey string `json:"secret_key,omitempty"`
}

func (s *Server) toApplicationResponse(a store.Application, secret string) applicationResponse {
	out := applicationResponse{
		ID: a.ID, Name: a.Name, PublishableKey: a.PublishableKey, SecretKeyLast4: a.SecretKeyLast4,
		Settings: settingsResponse{
			AllowedOrigins:     a.Settings.AllowedOrigins,
			SessionLifetimeSec: int(a.Settings.SessionLifetime / time.Second),
			SessionIdleTimeout: int(a.Settings.SessionIdleTimeout / time.Second),
			SignupEnabled:      a.Settings.SignupEnabled,
		},
		CreatedAt: a.CreatedAt, SecretKey: secret,
	}
	if s.tokens != nil {
		out.Issuer = s.tokens.Issuer(a.ID)
		out.JWKSURL = s.tokens.JWKSURL(a.ID)
	}
	return out
}

func (s *Server) handleListApplications(w nethttp.ResponseWriter, r *nethttp.Request) {
	list, err := s.apps.ListApplications(r.Context(), developerFrom(r).ID)
	if err != nil {
		s.internalError(w, "list applications", err)
		return
	}
	out := make([]applicationResponse, 0, len(list))
	for _, a := range list {
		out = append(out, s.toApplicationResponse(a, ""))
	}
	WriteJSON(w, nethttp.StatusOK, map[string]any{"applications": out})
}

func validateName(name string) (string, bool) {
	name = strings.TrimSpace(name)
	n := utf8.RuneCountInString(name)
	return name, n >= 1 && n <= maxAppNameLen
}

func (s *Server) handleCreateApplication(w nethttp.ResponseWriter, r *nethttp.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	name, ok := validateName(in.Name)
	if !ok {
		WriteError(w, nethttp.StatusUnprocessableEntity, "validation_error", "name must be 1-100 characters")
		return
	}
	pk, err := auth.NewPublishableKey()
	if err != nil {
		s.internalError(w, "create application: pk", err)
		return
	}
	sk, skHash, last4, err := auth.NewSecretKey()
	if err != nil {
		s.internalError(w, "create application: sk", err)
		return
	}
	app, err := s.apps.CreateApplication(r.Context(), store.NewApplication{
		DeveloperID: developerFrom(r).ID, Name: name, PublishableKey: pk, SecretKeyHash: skHash, SecretKeyLast4: last4,
	})
	if err != nil {
		s.internalError(w, "create application", err)
		return
	}
	if s.tokens != nil {
		// Best effort: the first key is also created lazily on first use.
		if err := s.tokens.EnsureKey(r.Context(), app.ID, s.opts.Now()); err != nil {
			s.log.Warn("create application: ensure signing key", "err", err, "application_id", app.ID)
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	WriteJSON(w, nethttp.StatusCreated, s.toApplicationResponse(app, sk))
}

func (s *Server) handleGetApplication(w nethttp.ResponseWriter, r *nethttp.Request) {
	app, ok := s.ownedApplication(w, r)
	if !ok {
		return
	}
	WriteJSON(w, nethttp.StatusOK, s.toApplicationResponse(app, ""))
}

// ownedApplication loads the application in the URL if the signed-in developer
// owns it. Someone else's application and a nonexistent one are both 404.
func (s *Server) ownedApplication(w nethttp.ResponseWriter, r *nethttp.Request) (store.Application, bool) {
	app, err := s.apps.GetApplication(r.Context(), developerFrom(r).ID, chi.URLParam(r, "id"))
	if errors.Is(err, store.ErrNotFound) {
		WriteError(w, nethttp.StatusNotFound, "not_found", "Application not found")
		return store.Application{}, false
	}
	if err != nil {
		s.internalError(w, "load application", err)
		return store.Application{}, false
	}
	return app, true
}

// normalizeOrigin accepts "scheme://host[:port]" for http and https only and
// returns it lower-cased with no trailing slash. Paths, queries, fragments,
// credentials and wildcards are refused.
func normalizeOrigin(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || strings.Contains(u.Host, "*") {
		return "", false
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host), true
}

func (s *Server) handleUpdateApplication(w nethttp.ResponseWriter, r *nethttp.Request) {
	app, ok := s.ownedApplication(w, r)
	if !ok {
		return
	}
	var in struct {
		Name               *string   `json:"name"`
		AllowedOrigins     *[]string `json:"allowed_origins"`
		SessionLifetimeSec *int      `json:"session_lifetime_seconds"`
		SessionIdleTimeout *int      `json:"session_idle_timeout_seconds"`
		SignupEnabled      *bool     `json:"signup_enabled"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}

	name, st := app.Name, app.Settings
	fail := func(msg string) {
		WriteError(w, nethttp.StatusUnprocessableEntity, "validation_error", msg)
	}
	if in.Name != nil {
		n, ok := validateName(*in.Name)
		if !ok {
			fail("name must be 1-100 characters")
			return
		}
		name = n
	}
	if in.AllowedOrigins != nil {
		if len(*in.AllowedOrigins) > maxAllowedOrigins {
			fail("at most 20 allowed origins")
			return
		}
		seen := map[string]bool{}
		origins := []string{}
		for _, o := range *in.AllowedOrigins {
			n, ok := normalizeOrigin(o)
			if !ok {
				fail("allowed_origins entries must look like https://example.com (http or https, no path, no wildcard)")
				return
			}
			if !seen[n] {
				seen[n] = true
				origins = append(origins, n)
			}
		}
		st.AllowedOrigins = origins
	}
	if in.SessionLifetimeSec != nil {
		st.SessionLifetime = time.Duration(*in.SessionLifetimeSec) * time.Second
	}
	if in.SessionIdleTimeout != nil {
		st.SessionIdleTimeout = time.Duration(*in.SessionIdleTimeout) * time.Second
	}
	if in.SignupEnabled != nil {
		st.SignupEnabled = *in.SignupEnabled
	}
	switch {
	case st.SessionLifetime < minSessionLifetime || st.SessionLifetime > maxSessionLifetime:
		fail("session_lifetime_seconds must be between 3600 (1 hour) and 31536000 (365 days)")
		return
	case st.SessionIdleTimeout < minIdleTimeout || st.SessionIdleTimeout > maxSessionLifetime:
		fail("session_idle_timeout_seconds must be between 300 (5 minutes) and 31536000 (365 days)")
		return
	case st.SessionIdleTimeout > st.SessionLifetime:
		fail("session_idle_timeout_seconds cannot exceed session_lifetime_seconds")
		return
	}

	updated, err := s.apps.UpdateApplication(r.Context(), developerFrom(r).ID, app.ID, name, st)
	if errors.Is(err, store.ErrNotFound) {
		WriteError(w, nethttp.StatusNotFound, "not_found", "Application not found")
		return
	}
	if err != nil {
		s.internalError(w, "update application", err)
		return
	}
	WriteJSON(w, nethttp.StatusOK, s.toApplicationResponse(updated, ""))
}

// handleRollSecretKey issues a new secret key. The old one stops working at once.
func (s *Server) handleRollSecretKey(w nethttp.ResponseWriter, r *nethttp.Request) {
	app, ok := s.ownedApplication(w, r)
	if !ok {
		return
	}
	sk, hash, last4, err := auth.NewSecretKey()
	if err != nil {
		s.internalError(w, "roll secret key: generate", err)
		return
	}
	updated, err := s.apps.RollSecretKey(r.Context(), developerFrom(r).ID, app.ID, hash, last4)
	if errors.Is(err, store.ErrNotFound) {
		WriteError(w, nethttp.StatusNotFound, "not_found", "Application not found")
		return
	}
	if err != nil {
		s.internalError(w, "roll secret key", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	WriteJSON(w, nethttp.StatusOK, s.toApplicationResponse(updated, sk))
}

// handleRotateSigningKey rotates one application's token signing key with the
// safe two-phase schedule: the new key is published now and signs from
// auth.KeyActivationDelay later.
func (s *Server) handleRotateSigningKey(w nethttp.ResponseWriter, r *nethttp.Request) {
	app, ok := s.ownedApplication(w, r)
	if !ok {
		return
	}
	if s.tokens == nil {
		WriteError(w, nethttp.StatusServiceUnavailable, "unavailable", "Token service is not configured")
		return
	}
	if err := s.tokens.EnsureKey(r.Context(), app.ID, s.opts.Now()); err != nil {
		s.internalError(w, "rotate: ensure key", err, "application_id", app.ID)
		return
	}
	kid, activeFrom, err := s.tokens.Rotate(r.Context(), app.ID, s.opts.Now(), auth.KeyActivationDelay)
	if err != nil {
		s.internalError(w, "rotate signing key", err, "application_id", app.ID)
		return
	}
	WriteJSON(w, nethttp.StatusOK, map[string]any{"kid": kid, "active_from": activeFrom})
}
