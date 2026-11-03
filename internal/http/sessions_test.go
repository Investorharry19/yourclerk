package http

import (
	"context"
	"io"
	"log/slog"
	nethttp "net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Investorharry19/yourclerk/internal/auth"
)

func oneApp(t *testing.T, mutate ...func(*Options)) (*env, applicationResponse) {
	e := newEnv(t, mutate...)
	app := e.createApp(e.developer("dev@example.com"), "App")
	return e, app
}

func TestSessionLifecycle(t *testing.T) {
	e, app := oneApp(t)
	a1, a2 := e.actor(app.PublishableKey), e.actor(app.PublishableKey)

	if st, _ := a1.me(); st != 401 {
		t.Fatalf("me before login: %d", st)
	}
	if st := a1.signup("Alice@Example.com", "password-1"); st != 201 {
		t.Fatalf("signup: %d", st)
	}
	if st := a1.login("alice@example.com", "password-1"); st != 200 {
		t.Fatalf("login: %d", st)
	}
	if st := a2.login("ALICE@example.com", "password-1"); st != 200 {
		t.Fatalf("second device login: %d", st)
	}
	id1, id2 := a1.sessionID(), a2.sessionID()
	if id1 == id2 {
		t.Fatal("two logins share a session")
	}

	_, body, _ := a1.call("GET", "/v1/sessions", "")
	list := decode[struct{ Sessions []sessionResponse }](t, body).Sessions
	if len(list) != 2 {
		t.Fatalf("sessions = %d", len(list))
	}
	for _, s := range list {
		if s.Current != (s.ID == id1) {
			t.Fatalf("current flag wrong: %+v", s)
		}
	}

	// Another device's session can be revoked, and only that one.
	if st, _, _ := a1.call("DELETE", "/v1/sessions/"+id2, ""); st != 204 {
		t.Fatalf("revoke other: %d", st)
	}
	if st, _ := a2.me(); st != 401 {
		t.Fatalf("revoked session still works: %d", st)
	}
	if st, _ := a1.me(); st != 200 {
		t.Fatalf("own session lost: %d", st)
	}
	if st, body, _ := a1.call("DELETE", "/v1/sessions/"+id2, ""); st != 404 || errCode(t, body) != "not_found" {
		t.Fatalf("double revoke: %d %s", st, body)
	}
	if st, _, _ := a1.call("DELETE", "/v1/sessions/not-a-uuid", ""); st != 404 {
		t.Fatalf("malformed id: %d", st)
	}

	if st, _, _ := a1.call("POST", "/v1/logout", ""); st != 204 {
		t.Fatalf("logout: %d", st)
	}
	if st, _ := a1.me(); st != 401 {
		t.Fatalf("me after logout: %d", st)
	}
}

// Session ids from another application are as good as nonexistent.
func TestCannotRevokeASessionOfAnotherApplication(t *testing.T) {
	w := newTwoApps(t)
	w.ua.signup("x@example.com", "password-1")
	w.ua.login("x@example.com", "password-1")
	w.ub.signup("x@example.com", "password-1")
	w.ub.login("x@example.com", "password-1")
	idA := w.ua.sessionID()

	if st, _, _ := w.ub.call("DELETE", "/v1/sessions/"+idA, ""); st != 404 {
		t.Fatalf("B revoked A's session: %d", st)
	}
	if st, _ := w.ua.me(); st != 200 {
		t.Fatalf("A's session was revoked through B: %d", st)
	}
	if st, _, _ := w.ub.call("POST", "/v1/sessions/"+idA+"/token", ""); st != 404 {
		t.Fatalf("B minted a token for A's session: %d", st)
	}
}

func TestLoginErrorsAreIdentical(t *testing.T) {
	e, app := oneApp(t)
	a := e.actor(app.PublishableKey)
	a.signup("real@example.com", "password-1")

	type res struct {
		st   int
		body string
	}
	var got []res
	for _, in := range []string{
		creds("real@example.com", "wrong-password"),
		creds("nobody@example.com", "password-1"),
		creds("not-an-email", "password-1"),
		creds("", ""),
	} {
		st, body, hdr := a.call("POST", "/v1/login", in)
		if len(hdr.Values("Set-Cookie")) != 0 {
			t.Fatalf("failed login set a cookie: %v", hdr.Values("Set-Cookie"))
		}
		got = append(got, res{st, body})
	}
	for _, r := range got {
		if r != got[0] || r.st != 401 || errCode(t, r.body) != "invalid_credentials" {
			t.Fatalf("login failures differ: %+v", got)
		}
	}
}

func TestSignupValidation(t *testing.T) {
	e, app := oneApp(t)
	a := e.actor(app.PublishableKey)
	for name, in := range map[string]string{
		"bad email":      creds("nope", "password-1"),
		"display name":   creds("Bob <bob@example.com>", "password-1"),
		"no domain dot":  creds("bob@localhost", "password-1"),
		"short password": creds("bob@example.com", "short"),
		"long password":  creds("bob@example.com", strings.Repeat("x", 129)),
	} {
		if st, _, _ := a.call("POST", "/v1/signup", in); st != 422 {
			t.Errorf("%s: %d, want 422", name, st)
		}
	}
	for name, in := range map[string]string{"not json": "{", "unknown field": `{"email":"a@b.co","password":"password-1","admin":true}`} {
		if st, _, _ := a.call("POST", "/v1/signup", in); st != 400 {
			t.Errorf("%s: %d, want 400", name, st)
		}
	}
}

func TestCookieFlags(t *testing.T) {
	for _, secure := range []bool{false, true} {
		e, app := oneApp(t, func(o *Options) { o.CookieSecure = secure })
		a := e.actor(app.PublishableKey)
		a.signup("c@example.com", "password-1")
		_, _, hdr := a.call("POST", "/v1/login", creds("c@example.com", "password-1"))
		raw := strings.Join(hdr.Values("Set-Cookie"), "\n")
		wantName := "session_" + auth.CookieSuffix(app.PublishableKey) + "="
		if !strings.HasPrefix(raw, wantName) {
			t.Fatalf("cookie %q does not start with %q", raw, wantName)
		}
		for _, f := range []string{"HttpOnly", "SameSite=Lax", "Path=/"} {
			if !strings.Contains(raw, f) {
				t.Errorf("secure=%v: cookie lacks %s: %s", secure, f, raw)
			}
		}
		if strings.Contains(raw, "Secure") != secure {
			t.Errorf("secure=%v: cookie = %s", secure, raw)
		}
	}
}

func TestLastActiveWritesAreThrottled(t *testing.T) {
	e, app := oneApp(t)
	a := e.actor(app.PublishableKey)
	a.signup("t@example.com", "password-1")
	a.login("t@example.com", "password-1")
	tenant := e.world.ForApp(app.ID).(*fakeTenant)

	for i := 0; i < 5; i++ {
		a.me()
	}
	if tenant.touches != 0 {
		t.Fatalf("%d writes within a minute", tenant.touches)
	}
	e.clock.Advance(2 * time.Minute)
	for i := 0; i < 5; i++ {
		a.me()
	}
	if tenant.touches != 1 {
		t.Fatalf("%d writes after two minutes, want 1", tenant.touches)
	}
}

func TestIssueTokenFlow(t *testing.T) {
	e, app := oneApp(t)
	a := e.actor(app.PublishableKey)
	a.signup("tok@example.com", "password-1")
	a.login("tok@example.com", "password-1")
	sid := a.sessionID()

	st, body, hdr := a.call("POST", "/v1/sessions/"+sid+"/token", "")
	if st != 200 {
		t.Fatalf("token: %d %s", st, body)
	}
	if hdr.Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", hdr.Get("Cache-Control"))
	}
	tr := decode[tokenResponse](t, body)
	if tr.TokenType != "Bearer" || tr.ExpiresIn != 60 {
		t.Fatalf("token response = %+v", tr)
	}
	claims, err := e.ts.Verify(context.Background(), app.ID, tr.Token, e.clock.Now())
	if err != nil || claims.SessionID != sid {
		t.Fatalf("verify: %v %+v", err, claims)
	}

	// Only the current session may mint tokens.
	a2 := e.actor(app.PublishableKey)
	a2.login("tok@example.com", "password-1")
	if st, _, _ := a.call("POST", "/v1/sessions/"+a2.sessionID()+"/token", ""); st != 404 {
		t.Fatalf("token for another session: %d", st)
	}
	if st, _, _ := e.call("POST", "/v1/sessions/"+sid+"/token", "", publishableKeyHeader, app.PublishableKey); st != 401 {
		t.Fatalf("token without a session cookie: %d", st)
	}

	// Revoked sessions get no more tokens.
	a.call("POST", "/v1/logout", "")
	if st, _, _ := a.call("POST", "/v1/sessions/"+sid+"/token", ""); st != 401 {
		t.Fatalf("token after logout: %d", st)
	}
}

func TestTokenEndpointsWithoutServiceReturn503(t *testing.T) {
	e, app := oneApp(t)
	e.actor(app.PublishableKey).signup("n@example.com", "password-1")

	// The same world behind a server that has no token service.
	h := NewServer(Deps{
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), DB: fakeDB{},
		Registry: e.world, Developers: e.world, Apps: e.world, Tenants: e.world,
		Options: Options{Now: e.clock.Now},
	}).Handler()
	srv := httptest.NewServer(h)
	defer srv.Close()

	jar, _ := cookiejar.New(nil)
	c := &nethttp.Client{Jar: jar}
	pk := []string{publishableKeyHeader, app.PublishableKey}
	if st, body, _ := send(t, c, srv.URL+"/v1/login", "POST", creds("n@example.com", "password-1"), pk...); st != 200 {
		t.Fatalf("login: %d %s", st, body)
	}
	_, body, _ := send(t, c, srv.URL+"/v1/me", "GET", "", pk...)
	sid := decode[struct {
		Session struct{ ID string }
	}](t, body).Session.ID

	if st, _, _ := send(t, c, srv.URL+"/v1/sessions/"+sid+"/token", "POST", "", pk...); st != 503 {
		t.Fatalf("token endpoint: %d, want 503", st)
	}
	if st, _, _ := send(t, c, srv.URL+"/apps/"+app.ID+"/.well-known/jwks.json", "GET", ""); st != 503 {
		t.Fatalf("jwks endpoint: %d, want 503", st)
	}
}
