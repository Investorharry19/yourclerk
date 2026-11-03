package http

import (
	"context"
	"errors"
	"net"
	nethttp "net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Investorharry19/yourclerk/internal/auth"
	"github.com/Investorharry19/yourclerk/internal/store"
)

const (
	// Each application gets its own cookie name, "session_<part of its
	// publishable key>", so one browser can hold sessions for several
	// applications on the same host without them colliding.
	sessionCookiePrefix = "session_"
	maxUserAgentLen     = 512

	// last_active_at is written at most this often per session, so a busy
	// client does not cause a database write on every request.
	touchInterval = time.Minute
)

// Options tunes server behaviour. The zero value is usable: Now defaults to
// time.Now and cookies to not Secure (set CookieSecure for anything served
// over https). Session lifetimes are per application, in its settings.
type Options struct {
	CookieSecure bool
	Now          func() time.Time
	// EnableDocs serves Swagger UI at /docs and the OpenAPI spec at /openapi.json.
	EnableDocs bool
}

func (o Options) withDefaults() Options {
	if o.Now == nil {
		o.Now = time.Now
	}
	return o
}

// --- context helpers -------------------------------------------------------

const (
	userCtxKey ctxKey = iota + 100
	sessionCtxKey
)

// UserFromContext returns the signed-in user set by the auth middleware.
func UserFromContext(ctx context.Context) (store.User, bool) {
	u, ok := ctx.Value(userCtxKey).(store.User)
	return u, ok
}

// SessionFromContext returns the current session set by the auth middleware.
func SessionFromContext(ctx context.Context) (store.Session, bool) {
	s, ok := ctx.Value(sessionCtxKey).(store.Session)
	return s, ok
}

// --- cookies ---------------------------------------------------------------

func (s *Server) setSessionCookie(w nethttp.ResponseWriter, app store.Application, token string, expires time.Time) {
	nethttp.SetCookie(w, &nethttp.Cookie{
		Name:     sessionCookieName(app),
		Value:    token,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(expires.Sub(s.opts.Now()).Seconds()),
		HttpOnly: true,
		Secure:   s.opts.CookieSecure,
		SameSite: nethttp.SameSiteLaxMode,
	})
}

func (s *Server) clearSessionCookie(w nethttp.ResponseWriter, app store.Application) {
	nethttp.SetCookie(w, &nethttp.Cookie{
		Name:     sessionCookieName(app),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.opts.CookieSecure,
		SameSite: nethttp.SameSiteLaxMode,
	})
}

func sessionCookieName(app store.Application) string {
	return sessionCookiePrefix + auth.CookieSuffix(app.PublishableKey)
}

func clientIP(r *nethttp.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// startSession creates a session for the user and sets the cookie. The token
// is always freshly generated on the server, so a token planted by an
// attacker before login is never accepted (no session fixation).
func (s *Server) startSession(w nethttp.ResponseWriter, r *nethttp.Request, userID string) error {
	token, hash, err := auth.NewSessionToken()
	if err != nil {
		return err
	}

	ua := r.UserAgent()
	if len(ua) > maxUserAgentLen {
		ua = ua[:maxUserAgentLen]
	}
	ua = strings.ToValidUTF8(ua, "")

	app, _ := ApplicationFromContext(r.Context())
	now := s.opts.Now()
	expiresAt := now.Add(app.Settings.SessionLifetime)
	if _, err := s.tenant(r).CreateSession(r.Context(), userID, hash, ua, clientIP(r), now, expiresAt); err != nil {
		return err
	}
	s.setSessionCookie(w, app, token, expiresAt)
	return nil
}

// --- middleware ------------------------------------------------------------

func writeUnauthorized(w nethttp.ResponseWriter) {
	WriteError(w, nethttp.StatusUnauthorized, "unauthorized", "Authentication required")
}

// requireAuth reads the session cookie, hashes it, finds the live session and
// puts the user and session in the request context. Missing, unknown, revoked
// and expired sessions all give the same 401.
func (s *Server) requireAuth(next nethttp.Handler) nethttp.Handler {
	return nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		app, _ := ApplicationFromContext(r.Context())
		c, err := r.Cookie(sessionCookieName(app))
		if err != nil || c.Value == "" {
			writeUnauthorized(w)
			return
		}

		now := s.opts.Now()
		sess, user, err := s.tenant(r).GetLiveSession(r.Context(), auth.HashToken(c.Value), now, now.Add(-app.Settings.SessionIdleTimeout))
		if errors.Is(err, store.ErrNotFound) {
			s.clearSessionCookie(w, app)
			writeUnauthorized(w)
			return
		}
		if err != nil {
			s.log.Error("auth: load session", "err", err)
			WriteError(w, nethttp.StatusInternalServerError, "internal_error", "Something went wrong")
			return
		}

		if now.Sub(sess.LastActiveAt) >= touchInterval {
			if err := s.tenant(r).TouchSession(r.Context(), sess.ID, now); err != nil {
				// Not fatal: the request is still authenticated.
				s.log.Warn("auth: touch session", "err", err, "session_id", sess.ID)
			}
		}

		ctx := context.WithValue(r.Context(), userCtxKey, user)
		ctx = context.WithValue(ctx, sessionCtxKey, sess)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// --- handlers --------------------------------------------------------------

func (s *Server) handleMe(w nethttp.ResponseWriter, r *nethttp.Request) {
	user, _ := UserFromContext(r.Context())
	sess, _ := SessionFromContext(r.Context())
	WriteJSON(w, nethttp.StatusOK, map[string]any{
		"user":    toUserResponse(user),
		"session": map[string]string{"id": sess.ID},
	})
}

func (s *Server) handleLogout(w nethttp.ResponseWriter, r *nethttp.Request) {
	app, _ := ApplicationFromContext(r.Context())
	user, _ := UserFromContext(r.Context())
	sess, _ := SessionFromContext(r.Context())

	if _, err := s.tenant(r).RevokeSession(r.Context(), user.ID, sess.ID, s.opts.Now()); err != nil {
		s.log.Error("logout: revoke session", "err", err, "session_id", sess.ID)
		WriteError(w, nethttp.StatusInternalServerError, "internal_error", "Something went wrong")
		return
	}
	s.clearSessionCookie(w, app)
	w.WriteHeader(nethttp.StatusNoContent)
}

type sessionResponse struct {
	ID           string    `json:"id"`
	UserAgent    string    `json:"user_agent"`
	IP           string    `json:"ip"`
	CreatedAt    time.Time `json:"created_at"`
	LastActiveAt time.Time `json:"last_active_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	Current      bool      `json:"current"`
}

func (s *Server) handleListSessions(w nethttp.ResponseWriter, r *nethttp.Request) {
	app, _ := ApplicationFromContext(r.Context())
	user, _ := UserFromContext(r.Context())
	current, _ := SessionFromContext(r.Context())

	now := s.opts.Now()
	list, err := s.tenant(r).ListLiveSessions(r.Context(), user.ID, now, now.Add(-app.Settings.SessionIdleTimeout))
	if err != nil {
		s.log.Error("list sessions", "err", err, "user_id", user.ID)
		WriteError(w, nethttp.StatusInternalServerError, "internal_error", "Something went wrong")
		return
	}

	out := make([]sessionResponse, 0, len(list))
	for _, sess := range list {
		out = append(out, sessionResponse{
			ID:           sess.ID,
			UserAgent:    sess.UserAgent,
			IP:           sess.IP,
			CreatedAt:    sess.CreatedAt,
			LastActiveAt: sess.LastActiveAt,
			ExpiresAt:    sess.ExpiresAt,
			Current:      sess.ID == current.ID,
		})
	}
	WriteJSON(w, nethttp.StatusOK, map[string]any{"sessions": out})
}

// handleRevokeSession revokes one of the caller's own sessions. Someone
// else's session, an already-revoked one and a malformed id all give the same
// 404, so the endpoint cannot be used to probe for other users' session ids.
func (s *Server) handleRevokeSession(w nethttp.ResponseWriter, r *nethttp.Request) {
	app, _ := ApplicationFromContext(r.Context())
	user, _ := UserFromContext(r.Context())
	current, _ := SessionFromContext(r.Context())
	id := chi.URLParam(r, "id")

	ok, err := s.tenant(r).RevokeSession(r.Context(), user.ID, id, s.opts.Now())
	if err != nil {
		s.log.Error("revoke session", "err", err, "session_id", id)
		WriteError(w, nethttp.StatusInternalServerError, "internal_error", "Something went wrong")
		return
	}
	if !ok {
		WriteError(w, nethttp.StatusNotFound, "not_found", "Session not found")
		return
	}
	if id == current.ID {
		s.clearSessionCookie(w, app)
	}
	w.WriteHeader(nethttp.StatusNoContent)
}
