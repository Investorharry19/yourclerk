package yourclerk

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func protectedHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := ClaimsFromContext(r.Context())
		if !ok {
			http.Error(w, "no claims in context", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"user": claims.UserID(), "session": claims.SessionID})
	})
}

func call(h http.Handler, authHeader string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "/protected", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestRequireAuth(t *testing.T) {
	clk := newClock()
	iss := newFakeIssuer(t, clk)
	key := iss.addKey("k1")

	var rec errorLog
	c := iss.client(clk, func(cfg *Config) { cfg.OnError = rec.record })
	h := c.RequireAuth(protectedHandler())

	good := iss.token(key)
	expired := iss.token(key, withClaim("exp", clk.Now().Add(-time.Hour).Unix()))
	forged := iss.token(iss.newKey("k1"))

	tests := []struct {
		name   string
		header string
		want   int
	}{
		{"valid", "Bearer " + good, 200},
		{"scheme is case-insensitive", "bearer " + good, 200},
		{"no header", "", 401},
		{"wrong scheme", "Basic dXNlcjpwYXNz", 401},
		{"scheme only", "Bearer", 401},
		{"empty token", "Bearer ", 401},
		{"token without scheme", good, 401},
		{"garbage", "Bearer not-a-token", 401},
		{"expired", "Bearer " + expired, 401},
		{"forged signature", "Bearer " + forged, 401},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rr := call(h, tc.header)
			if rr.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %s)", rr.Code, tc.want, rr.Body.String())
			}
			if tc.want == 401 && rr.Header().Get("WWW-Authenticate") == "" {
				t.Fatal("401 without WWW-Authenticate")
			}
		})
	}

	rr := call(h, "Bearer "+good)
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || body["user"] != testSubject || body["session"] != "sess-1" {
		t.Fatalf("handler saw %v (%v)", body, err)
	}
}

// Callers must not learn why a token was refused.
func TestRequireAuthDoesNotLeakReasons(t *testing.T) {
	clk := newClock()
	iss := newFakeIssuer(t, clk)
	key := iss.addKey("k1")
	var rec errorLog
	c := iss.client(clk, func(cfg *Config) { cfg.OnError = rec.record })
	h := c.RequireAuth(protectedHandler())

	expired := call(h, "Bearer "+iss.token(key, withClaim("exp", clk.Now().Add(-time.Hour).Unix())))
	forged := call(h, "Bearer "+iss.token(iss.newKey("k1")))
	missing := call(h, "")
	wrongIss := call(h, "Bearer "+iss.token(key, withClaim("iss", "https://evil.example")))

	for name, rr := range map[string]*httptest.ResponseRecorder{"forged": forged, "missing": missing, "wrong issuer": wrongIss} {
		if rr.Body.String() != expired.Body.String() {
			t.Errorf("%s response differs from expired:\n%s\n%s", name, rr.Body.String(), expired.Body.String())
		}
	}

	// ...but the operator does, through OnError.
	errs := rec.all()
	if len(errs) != 4 {
		t.Fatalf("OnError called %d times, want 4", len(errs))
	}
	if !errors.Is(errs[0], ErrTokenExpired) || !errors.Is(errs[1], ErrInvalidToken) || !errors.Is(errs[3], ErrWrongIssuer) {
		t.Fatalf("OnError reasons = %v", errs)
	}
}

func TestRequireAuthReturns503WhenKeysUnavailable(t *testing.T) {
	clk := newClock()
	iss := newFakeIssuer(t, clk)
	key := iss.addKey("k1")
	iss.setDown(true)
	h := iss.client(clk).RequireAuth(protectedHandler())

	rr := call(h, "Bearer "+iss.token(key))
	if rr.Code != 503 {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}

func TestClaimsFromContextWithoutMiddleware(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	if _, ok := ClaimsFromContext(req.Context()); ok {
		t.Fatal("claims present without middleware")
	}
}

func TestBearerToken(t *testing.T) {
	tests := map[string]string{
		"Bearer abc":   "abc",
		"bearer abc":   "abc",
		"BEARER abc":   "abc",
		"Bearer  abc ": "abc",
		"Basic abc":    "",
		"abc":          "",
		"":             "",
	}
	for header, want := range tests {
		req := httptest.NewRequest("GET", "/", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		if got := BearerToken(req); got != want {
			t.Errorf("BearerToken(%q) = %q, want %q", header, got, want)
		}
	}
}

// errorLog collects errors reported through Config.OnError.
type errorLog struct {
	mu   sync.Mutex
	errs []error
}

func (l *errorLog) record(_ *http.Request, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.errs = append(l.errs, err)
}

func (l *errorLog) all() []error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]error(nil), l.errs...)
}
