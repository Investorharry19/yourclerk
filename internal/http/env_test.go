package http

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	nethttp "net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Investorharry19/yourclerk/internal/auth"
)

type fakeDB struct{ err error }

func (f fakeDB) Ping(context.Context) error { return f.err }

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newTestClock() *testClock {
	return &testClock{t: time.Now().UTC().Truncate(time.Second)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// env is a running server over the in-memory world, with a controllable clock.
type env struct {
	t     *testing.T
	clock *testClock
	world *fakeWorld
	ts    *auth.TokenService
	srv   *httptest.Server
	url   string
}

func newEnv(t *testing.T, mutate ...func(*Options)) *env {
	t.Helper()
	e := &env{t: t, clock: newTestClock(), world: newFakeWorld()}
	e.srv = httptest.NewUnstartedServer(nil) // listener exists before Start, so the issuer URL is known
	e.url = "http://" + e.srv.Listener.Addr().String()

	ts, err := auth.NewTokenService(auth.NewMemoryKeyStores(), "http-test-secret-http-test-secret-12", e.url, 0)
	if err != nil {
		t.Fatal(err)
	}
	e.ts = ts
	opts := Options{Now: e.clock.Now, EnableDocs: true}
	for _, m := range mutate {
		m(&opts)
	}
	e.srv.Config.Handler = NewServer(Deps{
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), DB: fakeDB{},
		Registry: e.world, Developers: e.world, Apps: e.world, Tenants: e.world, Tokens: ts, Options: opts,
	}).Handler()
	e.srv.Start()
	t.Cleanup(e.srv.Close)
	return e
}

// call sends a request with optional header pairs and no cookies.
func (e *env) call(method, path, body string, hdr ...string) (int, string, nethttp.Header) {
	e.t.Helper()
	return send(e.t, nethttp.DefaultClient, e.url+path, method, body, hdr...)
}

func send(t *testing.T, c *nethttp.Client, url, method, body string, hdr ...string) (int, string, nethttp.Header) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := nethttp.NewRequest(method, url, rd)
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

func decode[T any](t *testing.T, body string) T {
	t.Helper()
	var v T
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatalf("bad JSON %q: %v", body, err)
	}
	return v
}

func errCode(t *testing.T, body string) string {
	t.Helper()
	var b errorBody
	if err := json.Unmarshal([]byte(body), &b); err != nil {
		t.Fatalf("not an error body: %q", body)
	}
	return b.Error.Code
}

func creds(email, pw string) string {
	b, _ := json.Marshal(credentials{Email: email, Password: pw})
	return string(b)
}

// --- developers and applications ---

// developer signs up and in on the platform API and returns the bearer token.
func (e *env) developer(email string) string {
	e.t.Helper()
	if st, body, _ := e.call("POST", "/v1/platform/signup", creds(email, "dev-password-1")); st != 201 {
		e.t.Fatalf("developer signup: %d %s", st, body)
	}
	st, body, _ := e.call("POST", "/v1/platform/login", creds(email, "dev-password-1"))
	if st != 200 {
		e.t.Fatalf("developer login: %d %s", st, body)
	}
	return decode[struct {
		Token string `json:"token"`
	}](e.t, body).Token
}

func bearerHdr(tok string) []string { return []string{"Authorization", "Bearer " + tok} }

func (e *env) createApp(devToken, name string) applicationResponse {
	e.t.Helper()
	st, body, _ := e.call("POST", "/v1/platform/applications", `{"name":"`+name+`"}`, bearerHdr(devToken)...)
	if st != 201 {
		e.t.Fatalf("create application: %d %s", st, body)
	}
	return decode[applicationResponse](e.t, body)
}

// --- end users ---

// actor is one browser talking to one application: a cookie jar plus its publishable key.
type actor struct {
	e  *env
	pk string
	c  *nethttp.Client
}

func (e *env) actor(pk string) *actor {
	jar, _ := cookiejar.New(nil)
	return &actor{e: e, pk: pk, c: &nethttp.Client{Jar: jar, CheckRedirect: func(*nethttp.Request, []*nethttp.Request) error { return nethttp.ErrUseLastResponse }}}
}

func (a *actor) call(method, path, body string) (int, string, nethttp.Header) {
	a.e.t.Helper()
	var hdr []string
	if a.pk != "" {
		hdr = []string{publishableKeyHeader, a.pk}
	}
	return send(a.e.t, a.c, a.e.url+path, method, body, hdr...)
}

func (a *actor) signup(email, pw string) int {
	st, _, _ := a.call("POST", "/v1/signup", creds(email, pw))
	return st
}

func (a *actor) login(email, pw string) int {
	st, _, _ := a.call("POST", "/v1/login", creds(email, pw))
	return st
}

func (a *actor) me() (int, string) {
	st, body, _ := a.call("GET", "/v1/me", "")
	return st, body
}

// sessionID returns the id of the actor's current session.
func (a *actor) sessionID() string {
	a.e.t.Helper()
	st, body := a.me()
	if st != 200 {
		a.e.t.Fatalf("me: %d %s", st, body)
	}
	return decode[struct {
		Session struct {
			ID string `json:"id"`
		} `json:"session"`
	}](a.e.t, body).Session.ID
}

// token mints an access token for the actor's current session.
func (a *actor) token() string {
	a.e.t.Helper()
	st, body, _ := a.call("POST", "/v1/sessions/"+a.sessionID()+"/token", "")
	if st != 200 {
		a.e.t.Fatalf("token: %d %s", st, body)
	}
	return decode[tokenResponse](a.e.t, body).Token
}
