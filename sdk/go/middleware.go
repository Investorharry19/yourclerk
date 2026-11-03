package yourclerk

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

type ctxKey struct{}

// ClaimsFromContext returns the verified claims that RequireAuth stored on the request.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(ctxKey{}).(*Claims)
	return c, ok
}

// BearerToken extracts the token from an "Authorization: Bearer <token>" header.
func BearerToken(r *http.Request) string {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(token)
}

// RequireAuth rejects requests that lack a valid access token and otherwise
// calls next with the claims available through ClaimsFromContext.
//
// Callers always get the same generic 401 whatever was wrong with the token;
// the reason goes to Config.OnError. If the issuer's keys cannot be fetched
// and none are cached it returns 503, since that is not the caller's fault.
func (c *Client) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := BearerToken(r)
		if token == "" {
			c.reject(w, r, http.StatusUnauthorized, "unauthorized", "Authentication required", errors.New("no bearer token"))
			return
		}
		claims, err := c.VerifyToken(r.Context(), token)
		if err != nil {
			if errors.Is(err, ErrJWKSUnavailable) {
				c.reject(w, r, http.StatusServiceUnavailable, "unavailable", "Authentication temporarily unavailable", err)
				return
			}
			c.reject(w, r, http.StatusUnauthorized, "unauthorized", "Authentication required", err)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, claims)))
	})
}

func (c *Client) reject(w http.ResponseWriter, r *http.Request, status int, code, message string, cause error) {
	if c.onError != nil {
		c.onError(r, cause)
	}
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="yourclerk"`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": message}})
}
