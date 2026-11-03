package http

import (
	"context"
	"fmt"
	nethttp "net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Investorharry19/yourclerk/internal/auth"
)

// TokenIssuer mints access tokens and publishes the keys that verify them.
// *auth.TokenService satisfies it.
type TokenIssuer interface {
	Issue(ctx context.Context, userID, sessionID string, now time.Time) (token string, expiresAt time.Time, err error)
	JWKS(ctx context.Context, now time.Time) (auth.JWKS, error)
}

// jwksCacheControl lets verifiers cache the JWKS for auth.JWKSCacheMaxAge.
// Rotation is safe with caching because a new key is published
// auth.KeyActivationDelay before it signs anything.
var jwksCacheControl = fmt.Sprintf("public, max-age=%d", int(auth.JWKSCacheMaxAge.Seconds()))

func (s *Server) handleJWKS(w nethttp.ResponseWriter, r *nethttp.Request) {
	if s.opts.Tokens == nil {
		WriteError(w, nethttp.StatusServiceUnavailable, "unavailable", "Token service is not configured")
		return
	}
	jwks, err := s.opts.Tokens.JWKS(r.Context(), s.opts.Now())
	if err != nil {
		s.log.Error("jwks", "err", err)
		WriteError(w, nethttp.StatusInternalServerError, "internal_error", "Something went wrong")
		return
	}
	w.Header().Set("Cache-Control", jwksCacheControl)
	WriteJSON(w, nethttp.StatusOK, jwks)
}

type tokenResponse struct {
	Token     string    `json:"token"`
	TokenType string    `json:"token_type"`
	ExpiresAt time.Time `json:"expires_at"`
	ExpiresIn int       `json:"expires_in"`
}

// handleIssueToken mints a short-lived access token for the caller's current
// session. Because it runs behind requireAuth, a revoked or expired session
// cannot get new tokens, so revocation takes effect within one token lifetime.
// Only the current session can mint tokens: any other id is a 404, whether it
// belongs to someone else, to the caller's other device, or to nobody.
func (s *Server) handleIssueToken(w nethttp.ResponseWriter, r *nethttp.Request) {
	if s.opts.Tokens == nil {
		WriteError(w, nethttp.StatusServiceUnavailable, "unavailable", "Token service is not configured")
		return
	}
	user, _ := UserFromContext(r.Context())
	current, _ := SessionFromContext(r.Context())
	if chi.URLParam(r, "id") != current.ID {
		WriteError(w, nethttp.StatusNotFound, "not_found", "Session not found")
		return
	}

	now := s.opts.Now()
	token, exp, err := s.opts.Tokens.Issue(r.Context(), user.ID, current.ID, now)
	if err != nil {
		s.log.Error("issue token", "err", err, "session_id", current.ID)
		WriteError(w, nethttp.StatusInternalServerError, "internal_error", "Something went wrong")
		return
	}

	// Tokens must never be cached by browsers or proxies.
	w.Header().Set("Cache-Control", "no-store")
	WriteJSON(w, nethttp.StatusOK, tokenResponse{
		Token:     token,
		TokenType: "Bearer",
		ExpiresAt: exp,
		ExpiresIn: int(exp.Sub(now).Seconds()),
	})
}
