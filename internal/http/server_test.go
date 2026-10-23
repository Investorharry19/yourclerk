package http

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	nethttp "net/http"
	"net/http/httptest"
	"testing"
)

type fakeDB struct{ err error }

func (f fakeDB) Ping(context.Context) error { return f.err }

func newTestServer(db Pinger) nethttp.Handler {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewServer(log, db, nil).Handler()
}

func TestHealthz(t *testing.T) {
	tests := []struct {
		name       string
		dbErr      error
		wantStatus int
		wantDB     string
	}{
		{"database up", nil, nethttp.StatusOK, "up"},
		{"database down", errors.New("boom"), nethttp.StatusServiceUnavailable, "down"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestServer(fakeDB{err: tc.dbErr})
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, httptest.NewRequest(nethttp.MethodGet, "/healthz", nil))

			if rr.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rr.Code, tc.wantStatus)
			}
			var body map[string]string
			if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
				t.Fatalf("bad json: %v", err)
			}
			if body["database"] != tc.wantDB {
				t.Fatalf("database = %q, want %q", body["database"], tc.wantDB)
			}
		})
	}
}

func TestRequestIDHeader(t *testing.T) {
	h := newTestServer(fakeDB{})

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(nethttp.MethodGet, "/healthz", nil))
	if rr.Header().Get("X-Request-ID") == "" {
		t.Fatal("expected generated X-Request-ID")
	}

	req := httptest.NewRequest(nethttp.MethodGet, "/healthz", nil)
	req.Header.Set("X-Request-ID", "abc123")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if got := rr.Header().Get("X-Request-ID"); got != "abc123" {
		t.Fatalf("X-Request-ID = %q, want abc123", got)
	}
}
