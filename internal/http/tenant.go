package http

import (
	"context"
	"errors"
	nethttp "net/http"
	"strings"

	"github.com/Investorharry19/yourclerk/internal/auth"
	"github.com/Investorharry19/yourclerk/internal/store"
)

const publishableKeyHeader = "X-Publishable-Key"

const (
	appCtxKey ctxKey = iota + 200
	tenantCtxKey
	developerCtxKey
)

// ApplicationFromContext returns the application a request was resolved to.
func ApplicationFromContext(ctx context.Context) (store.Application, bool) {
	a, ok := ctx.Value(appCtxKey).(store.Application)
	return a, ok
}

// tenant returns the data handle for the request's application. It only exists
// after resolveApplication or requireSecretKey has run, and is bound to that
// one application, so handlers cannot reach another tenant's rows.
func (s *Server) tenant(r *nethttp.Request) store.Tenant {
	t, _ := r.Context().Value(tenantCtxKey).(store.Tenant)
	return t
}

func (s *Server) withApplication(r *nethttp.Request, app store.Application) *nethttp.Request {
	ctx := context.WithValue(r.Context(), appCtxKey, app)
	ctx = context.WithValue(ctx, tenantCtxKey, s.tenants.ForApp(app.ID))
	return r.WithContext(ctx)
}

func (s *Server) internalError(w nethttp.ResponseWriter, msg string, err error, kv ...any) {
	s.log.Error(msg, append([]any{"err", err}, kv...)...)
	WriteError(w, nethttp.StatusInternalServerError, "internal_error", "Something went wrong")
}

// resolveApplication turns the X-Publishable-Key header into an application.
// A missing, malformed or unknown key is a 401 before any handler runs, so no
// end-user endpoint can execute without a tenant.
func (s *Server) resolveApplication(next nethttp.Handler) nethttp.Handler {
	return nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		key := r.Header.Get(publishableKeyHeader)
		if !auth.IsPublishableKey(key) {
			WriteError(w, nethttp.StatusUnauthorized, "invalid_publishable_key",
				"A valid publishable key is required in the "+publishableKeyHeader+" header")
			return
		}
		app, err := s.registry.ApplicationByPublishableKey(r.Context(), key)
		if errors.Is(err, store.ErrNotFound) {
			WriteError(w, nethttp.StatusUnauthorized, "invalid_publishable_key",
				"A valid publishable key is required in the "+publishableKeyHeader+" header")
			return
		}
		if err != nil {
			s.internalError(w, "resolve application", err)
			return
		}
		next.ServeHTTP(w, s.withApplication(r, app))
	})
}

// bearer extracts the token from "Authorization: Bearer <token>".
func bearer(r *nethttp.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) < 8 || !strings.EqualFold(h[:7], "bearer ") {
		return ""
	}
	return strings.TrimSpace(h[7:])
}

// requireSecretKey authorises a developer's backend. Only a secret key works:
// a publishable key, which is public by design, is rejected here no matter
// how it is presented.
func (s *Server) requireSecretKey(next nethttp.Handler) nethttp.Handler {
	return nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		key := bearer(r)
		if !auth.IsSecretKey(key) {
			WriteError(w, nethttp.StatusUnauthorized, "invalid_secret_key", "A valid secret key is required")
			return
		}
		app, err := s.registry.ApplicationBySecretKeyHash(r.Context(), auth.HashSecretKey(key))
		if errors.Is(err, store.ErrNotFound) {
			WriteError(w, nethttp.StatusUnauthorized, "invalid_secret_key", "A valid secret key is required")
			return
		}
		if err != nil {
			s.internalError(w, "resolve secret key", err)
			return
		}
		next.ServeHTTP(w, s.withApplication(r, app))
	})
}
