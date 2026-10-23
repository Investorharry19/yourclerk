package http

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	nethttp "net/http"
	"time"
)

type ctxKey int

const requestIDKey ctxKey = iota

// RequestIDFromContext returns the request ID set by the RequestID middleware.
func RequestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

// RequestID assigns each request an ID (or reuses a sane incoming one),
// stores it in the context and returns it in the X-Request-ID header.
func RequestID(next nethttp.Handler) nethttp.Handler {
	return nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" || len(id) > 64 {
			b := make([]byte, 8)
			_, _ = rand.Read(b)
			id = hex.EncodeToString(b)
		}
		w.Header().Set("X-Request-ID", id)
		ctx := context.WithValue(r.Context(), requestIDKey, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type statusRecorder struct {
	nethttp.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Logger writes one structured log line per request.
func Logger(log *slog.Logger) func(nethttp.Handler) nethttp.Handler {
	return func(next nethttp.Handler) nethttp.Handler {
		return nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: nethttp.StatusOK}
			next.ServeHTTP(rec, r)
			log.Info("request",
				"request_id", RequestIDFromContext(r.Context()),
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"duration_ms", time.Since(start).Milliseconds(),
			)
		})
	}
}

// Recoverer turns panics into a 500 response instead of killing the connection.
func Recoverer(log *slog.Logger) func(nethttp.Handler) nethttp.Handler {
	return func(next nethttp.Handler) nethttp.Handler {
		return nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					log.Error("panic", "request_id", RequestIDFromContext(r.Context()), "panic", rec)
					WriteError(w, nethttp.StatusInternalServerError, "internal_error", "Something went wrong")
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
