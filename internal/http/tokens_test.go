package http

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Investorharry19/yourclerk/internal/auth"
)

const (
	httpTestIssuer = "http://issuer.test"
	httpTestSecret = "http-test-secret-http-test-secret-123456"
)

func newTokenServer(t *testing.T) (*httptest.Server, *auth.TokenService) {
	t.Helper()
	ts, err := auth.NewTokenService(auth.NewMemoryKeyStore(), httpTestSecret, httpTestIssuer, "yourclerk", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	users := newFakeUsers()
	h := newSessionsServer(users, newFakeSessions(users), Options{Tokens: ts})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, ts
}

func meSessionID(t *testing.T, srvURL string, body string) string {
	t.Helper()
	var out struct {
		Session struct {
			ID string `json:"id"`
		} `json:"session"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil || out.Session.ID == "" {
		t.Fatalf("no session id in /me response %q: %v", body, err)
	}
	return out.Session.ID
}

func TestIssueTokenFlow(t *testing.T) {
	srv, ts := newTokenServer(t)
	signup(t, srv.URL, "alice@example.com", "correct horse")
	c := loginClient(t, srv.URL, "alice@example.com", "correct horse")

	code, body := do(t, c, "GET", srv.URL+"/v1/me", "")
	if code != 200 {
		t.Fatalf("/me = %d", code)
	}
	sid := meSessionID(t, srv.URL, body)

	code, body = do(t, c, "POST", srv.URL+"/v1/sessions/"+sid+"/token", "")
	if code != 200 {
		t.Fatalf("issue token = %d %s", code, body)
	}
	var tr tokenResponse
	if err := json.Unmarshal([]byte(body), &tr); err != nil {
		t.Fatal(err)
	}
	if tr.TokenType != "Bearer" || tr.ExpiresIn != 60 || strings.Count(tr.Token, ".") != 2 {
		t.Fatalf("bad token response: %+v", tr)
	}

	claims, err := ts.Verify(context.Background(), tr.Token, time.Now())
	if err != nil {
		t.Fatalf("issued token does not verify: %v", err)
	}
	if claims.SessionID != sid || claims.Issuer != httpTestIssuer || claims.Subject == "" {
		t.Fatalf("claims = %+v", claims)
	}
}

func TestIssueTokenIsNotCacheable(t *testing.T) {
	srv, _ := newTokenServer(t)
	signup(t, srv.URL, "alice@example.com", "correct horse")
	c := loginClient(t, srv.URL, "alice@example.com", "correct horse")
	_, body := do(t, c, "GET", srv.URL+"/v1/me", "")
	sid := meSessionID(t, srv.URL, body)

	resp, err := c.Post(srv.URL+"/v1/sessions/"+sid+"/token", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
}

func TestIssueTokenAuthorization(t *testing.T) {
	srv, _ := newTokenServer(t)
	signup(t, srv.URL, "alice@example.com", "correct horse")
	signup(t, srv.URL, "bob@example.com", "battery staple")

	laptop := loginClient(t, srv.URL, "alice@example.com", "correct horse")
	phone := loginClient(t, srv.URL, "alice@example.com", "correct horse")
	bob := loginClient(t, srv.URL, "bob@example.com", "battery staple")

	_, body := do(t, laptop, "GET", srv.URL+"/v1/me", "")
	laptopSID := meSessionID(t, srv.URL, body)
	_, body = do(t, phone, "GET", srv.URL+"/v1/me", "")
	phoneSID := meSessionID(t, srv.URL, body)
	_, body = do(t, bob, "GET", srv.URL+"/v1/me", "")
	bobSID := meSessionID(t, srv.URL, body)

	// No cookie: 401.
	anon := newJarClient(t)
	if code, _ := do(t, anon, "POST", srv.URL+"/v1/sessions/"+laptopSID+"/token", ""); code != 401 {
		t.Fatalf("anonymous = %d, want 401", code)
	}
	// Someone else's session, another of your own devices, and nonsense all give 404.
	for name, id := range map[string]string{"other user": bobSID, "own other device": phoneSID, "garbage": "not-a-uuid"} {
		if code, _ := do(t, laptop, "POST", srv.URL+"/v1/sessions/"+id+"/token", ""); code != 404 {
			t.Errorf("%s = %d, want 404", name, code)
		}
	}
	// Your own current session works.
	if code, _ := do(t, laptop, "POST", srv.URL+"/v1/sessions/"+laptopSID+"/token", ""); code != 200 {
		t.Fatalf("own session = %d, want 200", code)
	}
}

func TestRevokedSessionGetsNoMoreTokens(t *testing.T) {
	srv, _ := newTokenServer(t)
	signup(t, srv.URL, "alice@example.com", "correct horse")
	laptop := loginClient(t, srv.URL, "alice@example.com", "correct horse")
	phone := loginClient(t, srv.URL, "alice@example.com", "correct horse")

	_, body := do(t, phone, "GET", srv.URL+"/v1/me", "")
	phoneSID := meSessionID(t, srv.URL, body)
	if code, _ := do(t, phone, "POST", srv.URL+"/v1/sessions/"+phoneSID+"/token", ""); code != 200 {
		t.Fatalf("before revoke = %d", code)
	}

	if code, _ := do(t, laptop, "DELETE", srv.URL+"/v1/sessions/"+phoneSID, ""); code != 204 {
		t.Fatalf("revoke = %d", code)
	}
	if code, _ := do(t, phone, "POST", srv.URL+"/v1/sessions/"+phoneSID+"/token", ""); code != 401 {
		t.Fatalf("after revoke = %d, want 401", code)
	}
}

func TestJWKSEndpoint(t *testing.T) {
	srv, ts := newTokenServer(t)
	if err := ts.EnsureKey(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}

	resp, err := srv.Client().Get(srv.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("jwks = %d", resp.StatusCode)
	}
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "max-age=300") {
		t.Fatalf("Cache-Control = %q", cc)
	}

	var raw map[string][]map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatal(err)
	}
	keys := raw["keys"]
	if len(keys) != 1 {
		t.Fatalf("keys = %v", keys)
	}
	k := keys[0]
	for _, f := range []string{"kty", "crv", "x", "y", "kid", "alg", "use"} {
		if k[f] == "" {
			t.Errorf("JWK missing %q: %v", f, k)
		}
	}
	if _, leaked := k["d"]; leaked {
		t.Fatal("JWKS exposes a private key component")
	}
}

func TestTokenEndpointsWithoutServiceReturn503(t *testing.T) {
	users := newFakeUsers()
	srv := httptest.NewServer(newSessionsServer(users, newFakeSessions(users), Options{}))
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Fatalf("jwks without service = %d, want 503", resp.StatusCode)
	}
}
