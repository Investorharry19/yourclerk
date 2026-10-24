package http

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	nethttp "net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Investorharry19/yourclerk/internal/store"
)

// --- fakes -----------------------------------------------------------------

func (f *fakeUsers) byID(id string) (store.User, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, u := range f.users {
		if u.ID == id {
			return u, true
		}
	}
	return store.User{}, false
}

type fakeSession struct {
	store.Session
	hash    string
	revoked bool
}

// fakeSessions is an in-memory SessionStore with the same liveness rules as the SQL.
type fakeSessions struct {
	mu      sync.Mutex
	users   *fakeUsers
	all     []*fakeSession
	touches int
}

func newFakeSessions(users *fakeUsers) *fakeSessions { return &fakeSessions{users: users} }

func (f *fakeSessions) live(s *fakeSession, now, idleCutoff time.Time) bool {
	return !s.revoked && s.ExpiresAt.After(now) && s.LastActiveAt.After(idleCutoff)
}

func (f *fakeSessions) CreateSession(_ context.Context, userID string, tokenHash []byte, ua, ip string, now, expiresAt time.Time) (store.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := store.Session{
		ID:     fmt.Sprintf("00000000-0000-4000-8000-%012d", len(f.all)+1),
		UserID: userID, UserAgent: ua, IP: ip,
		CreatedAt: now, LastActiveAt: now, ExpiresAt: expiresAt,
	}
	f.all = append(f.all, &fakeSession{Session: s, hash: string(tokenHash)})
	return s, nil
}

func (f *fakeSessions) GetLiveSession(_ context.Context, tokenHash []byte, now, idleCutoff time.Time) (store.Session, store.User, error) {
	f.mu.Lock()
	var found *fakeSession
	for _, s := range f.all {
		if s.hash == string(tokenHash) && f.live(s, now, idleCutoff) {
			found = s
		}
	}
	var sess store.Session
	if found != nil {
		sess = found.Session
	}
	f.mu.Unlock()

	if found == nil {
		return store.Session{}, store.User{}, store.ErrNotFound
	}
	user, ok := f.users.byID(sess.UserID)
	if !ok {
		return store.Session{}, store.User{}, store.ErrNotFound
	}
	return sess, user, nil
}

func (f *fakeSessions) TouchSession(_ context.Context, id string, now time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.all {
		if s.ID == id {
			s.LastActiveAt = now
			f.touches++
		}
	}
	return nil
}

func (f *fakeSessions) ListLiveSessions(_ context.Context, userID string, now, idleCutoff time.Time) ([]store.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []store.Session
	for i := len(f.all) - 1; i >= 0; i-- { // newest first
		if s := f.all[i]; s.UserID == userID && f.live(s, now, idleCutoff) {
			out = append(out, s.Session)
		}
	}
	return out, nil
}

func (f *fakeSessions) RevokeSession(_ context.Context, userID, sessionID string, _ time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.all {
		if s.ID == sessionID && s.UserID == userID && !s.revoked {
			s.revoked = true
			return true, nil
		}
	}
	return false, nil
}

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newTestClock() *testClock {
	return &testClock{t: time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)}
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

// --- helpers ---------------------------------------------------------------

func newJarClient(t *testing.T) *nethttp.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &nethttp.Client{Jar: jar}
}

func do(t *testing.T, c *nethttp.Client, method, url, body string) (int, string) {
	t.Helper()
	req, err := nethttp.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func cookieValue(t *testing.T, c *nethttp.Client, base string) string {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == sessionCookieName {
			return ck.Value
		}
	}
	return ""
}

func signup(t *testing.T, base, email, pw string) {
	t.Helper()
	if code, body := do(t, nethttp.DefaultClient, "POST", base+"/v1/signup", creds(email, pw)); code != 201 {
		t.Fatalf("signup %s: %d %s", email, code, body)
	}
}

func loginClient(t *testing.T, base, email, pw string) *nethttp.Client {
	t.Helper()
	c := newJarClient(t)
	if code, body := do(t, c, "POST", base+"/v1/login", creds(email, pw)); code != 200 {
		t.Fatalf("login %s: %d %s", email, code, body)
	}
	return c
}

func listSessions(t *testing.T, c *nethttp.Client, base string) []sessionResponse {
	t.Helper()
	code, body := do(t, c, "GET", base+"/v1/sessions", "")
	if code != 200 {
		t.Fatalf("list sessions: %d %s", code, body)
	}
	var out struct {
		Sessions []sessionResponse `json:"sessions"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("bad json %q: %v", body, err)
	}
	return out.Sessions
}

// --- tests -----------------------------------------------------------------

func TestSessionLifecycle(t *testing.T) {
	users := newFakeUsers()
	sessions := newFakeSessions(users)
	srv := httptest.NewServer(newSessionsServer(users, sessions, Options{}))
	defer srv.Close()

	signup(t, srv.URL, "alice@example.com", "correct horse")

	c := newJarClient(t)
	if code, _ := do(t, c, "GET", srv.URL+"/v1/me", ""); code != 401 {
		t.Fatalf("/me without cookie = %d, want 401", code)
	}

	if code, body := do(t, c, "POST", srv.URL+"/v1/login", creds("alice@example.com", "correct horse")); code != 200 {
		t.Fatalf("login = %d %s", code, body)
	}
	code, body := do(t, c, "GET", srv.URL+"/v1/me", "")
	if code != 200 || !strings.Contains(body, "alice@example.com") {
		t.Fatalf("/me with cookie = %d %s", code, body)
	}

	// The database (here: the fake) must never hold the raw token.
	token := cookieValue(t, c, srv.URL)
	if token == "" {
		t.Fatal("no session cookie in jar")
	}
	for _, s := range sessions.all {
		if strings.Contains(s.hash, token) || s.hash == token {
			t.Fatal("raw session token stored")
		}
	}

	if code, _ := do(t, c, "POST", srv.URL+"/v1/logout", ""); code != 204 {
		t.Fatalf("logout = %d, want 204", code)
	}
	if code, _ := do(t, c, "GET", srv.URL+"/v1/me", ""); code != 401 {
		t.Fatalf("/me after logout = %d, want 401", code)
	}

	// A cookie copied before logout must be dead too.
	req, _ := nethttp.NewRequest("GET", srv.URL+"/v1/me", nil)
	req.AddCookie(&nethttp.Cookie{Name: sessionCookieName, Value: token})
	resp, err := nethttp.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("replayed cookie = %d, want 401", resp.StatusCode)
	}
}

func TestLoginCookieFlags(t *testing.T) {
	for _, secure := range []bool{true, false} {
		t.Run(fmt.Sprintf("secure=%v", secure), func(t *testing.T) {
			users := newFakeUsers()
			h := newSessionsServer(users, newFakeSessions(users), Options{CookieSecure: secure})
			post(h, "/v1/signup", creds("alice@example.com", "correct horse"))

			rr := post(h, "/v1/login", creds("alice@example.com", "correct horse"))
			if rr.Code != 200 {
				t.Fatalf("login = %d %s", rr.Code, rr.Body.String())
			}

			var ck *nethttp.Cookie
			for _, c := range rr.Result().Cookies() {
				if c.Name == sessionCookieName {
					ck = c
				}
			}
			if ck == nil {
				t.Fatal("no session cookie set")
			}
			if ck.Value == "" || !ck.HttpOnly || ck.SameSite != nethttp.SameSiteLaxMode || ck.Path != "/" || ck.Secure != secure {
				t.Fatalf("bad cookie flags: %+v", ck)
			}
			if ck.Expires.IsZero() {
				t.Fatal("cookie has no expiry")
			}
		})
	}
}

func TestFailedLoginSetsNoCookie(t *testing.T) {
	users := newFakeUsers()
	h := newSessionsServer(users, newFakeSessions(users), Options{})
	post(h, "/v1/signup", creds("alice@example.com", "correct horse"))

	rr := post(h, "/v1/login", creds("alice@example.com", "wrong password"))
	if len(rr.Result().Cookies()) != 0 {
		t.Fatalf("failed login set cookies: %v", rr.Result().Cookies())
	}
}

func TestRevokeOneSessionKeepsOthers(t *testing.T) {
	users := newFakeUsers()
	srv := httptest.NewServer(newSessionsServer(users, newFakeSessions(users), Options{}))
	defer srv.Close()

	signup(t, srv.URL, "alice@example.com", "correct horse")
	signup(t, srv.URL, "bob@example.com", "battery staple")

	laptop := loginClient(t, srv.URL, "alice@example.com", "correct horse")
	phone := loginClient(t, srv.URL, "alice@example.com", "correct horse")
	bob := loginClient(t, srv.URL, "bob@example.com", "battery staple")

	list := listSessions(t, laptop, srv.URL)
	if len(list) != 2 {
		t.Fatalf("alice has %d sessions, want 2", len(list))
	}
	var current, otherID string
	for _, s := range list {
		if s.Current {
			current = s.ID
		} else {
			otherID = s.ID
		}
	}
	if current == "" || otherID == "" {
		t.Fatalf("expected one current and one other session: %+v", list)
	}

	// Alice cannot revoke Bob's session, and cannot tell it exists.
	bobSession := listSessions(t, bob, srv.URL)[0].ID
	if code, _ := do(t, laptop, "DELETE", srv.URL+"/v1/sessions/"+bobSession, ""); code != 404 {
		t.Fatalf("revoking another user's session = %d, want 404", code)
	}
	if code, _ := do(t, bob, "GET", srv.URL+"/v1/me", ""); code != 200 {
		t.Fatalf("bob was affected: /me = %d", code)
	}
	if code, _ := do(t, laptop, "DELETE", srv.URL+"/v1/sessions/not-a-uuid", ""); code != 404 {
		t.Fatalf("malformed id = %d, want 404", code)
	}

	// Revoking the phone leaves the laptop alive.
	if code, _ := do(t, laptop, "DELETE", srv.URL+"/v1/sessions/"+otherID, ""); code != 204 {
		t.Fatalf("revoke = %d, want 204", code)
	}
	if code, _ := do(t, phone, "GET", srv.URL+"/v1/me", ""); code != 401 {
		t.Fatalf("revoked session /me = %d, want 401", code)
	}
	if code, _ := do(t, laptop, "GET", srv.URL+"/v1/me", ""); code != 200 {
		t.Fatalf("other session /me = %d, want 200", code)
	}
	if got := listSessions(t, laptop, srv.URL); len(got) != 1 || got[0].ID != current {
		t.Fatalf("sessions after revoke = %+v", got)
	}
}

func TestSessionExpiry(t *testing.T) {
	setup := func(t *testing.T) (nethttp.Handler, *testClock, *nethttp.Cookie) {
		t.Helper()
		clock := newTestClock()
		users := newFakeUsers()
		h := newSessionsServer(users, newFakeSessions(users), Options{Now: clock.Now})
		post(h, "/v1/signup", creds("alice@example.com", "correct horse"))
		rr := post(h, "/v1/login", creds("alice@example.com", "correct horse"))
		if rr.Code != 200 {
			t.Fatalf("login = %d %s", rr.Code, rr.Body.String())
		}
		for _, c := range rr.Result().Cookies() {
			if c.Name == sessionCookieName {
				return h, clock, c
			}
		}
		t.Fatal("no cookie")
		return nil, nil, nil
	}
	me := func(h nethttp.Handler, ck *nethttp.Cookie) int {
		req := httptest.NewRequest("GET", "/v1/me", nil)
		req.AddCookie(ck)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}

	t.Run("idle timeout", func(t *testing.T) {
		h, clock, ck := setup(t)
		clock.Advance(6 * 24 * time.Hour)
		if got := me(h, ck); got != 200 {
			t.Fatalf("day 6 = %d, want 200", got)
		}
		clock.Advance(8 * 24 * time.Hour) // unused for 8 days
		if got := me(h, ck); got != 401 {
			t.Fatalf("after 8 idle days = %d, want 401", got)
		}
	})

	t.Run("absolute timeout despite activity", func(t *testing.T) {
		h, clock, ck := setup(t)
		for day := 1; day <= 29; day++ {
			clock.Advance(24 * time.Hour)
			if got := me(h, ck); got != 200 {
				t.Fatalf("day %d = %d, want 200", day, got)
			}
		}
		clock.Advance(2 * 24 * time.Hour) // day 31, active the whole time
		if got := me(h, ck); got != 401 {
			t.Fatalf("day 31 = %d, want 401", got)
		}
	})
}

func TestLastActiveWritesAreThrottled(t *testing.T) {
	clock := newTestClock()
	users := newFakeUsers()
	sessions := newFakeSessions(users)
	h := newSessionsServer(users, sessions, Options{Now: clock.Now})
	post(h, "/v1/signup", creds("alice@example.com", "correct horse"))
	rr := post(h, "/v1/login", creds("alice@example.com", "correct horse"))
	ck := rr.Result().Cookies()[0]

	hit := func() {
		req := httptest.NewRequest("GET", "/v1/me", nil)
		req.AddCookie(ck)
		h.ServeHTTP(httptest.NewRecorder(), req)
	}

	hit()
	hit()
	if sessions.touches != 0 {
		t.Fatalf("touches right after login = %d, want 0", sessions.touches)
	}
	clock.Advance(2 * time.Minute)
	hit()
	hit()
	hit()
	if sessions.touches != 1 {
		t.Fatalf("touches after 2 minutes = %d, want 1", sessions.touches)
	}
}
