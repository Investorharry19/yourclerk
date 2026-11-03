package http

import (
	"context"
	"encoding/base64"
	"encoding/json"
	nethttp "net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Investorharry19/yourclerk/internal/auth"
)

type twoApps struct {
	*env
	dev  string
	a, b applicationResponse
	ua   *actor // a browser talking to application A
	ub   *actor
}

func newTwoApps(t *testing.T, mutate ...func(*Options)) *twoApps {
	e := newEnv(t, mutate...)
	dev := e.developer("dev@example.com")
	w := &twoApps{env: e, dev: dev, a: e.createApp(dev, "App A"), b: e.createApp(dev, "App B")}
	w.ua, w.ub = e.actor(w.a.PublishableKey), e.actor(w.b.PublishableKey)
	return w
}

func userID(t *testing.T, body string) string {
	t.Helper()
	return decode[struct{ User userResponse }](t, body).User.ID
}

// --- Stage 4 pass criteria --------------------------------------------------

// The same email can exist in two applications with different passwords, and
// neither password works in the other application.
func TestSameEmailInTwoApplicationsWithDifferentPasswords(t *testing.T) {
	w := newTwoApps(t)
	const email = "alice@example.com"

	if st := w.ua.signup(email, "password-for-A"); st != 201 {
		t.Fatalf("signup in A: %d", st)
	}
	if st := w.ub.signup(email, "password-for-B"); st != 201 {
		t.Fatalf("same email in B refused: %d", st)
	}
	if st := w.ua.signup(email, "another-password"); st != 409 {
		t.Fatalf("duplicate inside A: %d, want 409", st)
	}
	if st := w.ua.login(email, "password-for-B"); st != 401 {
		t.Fatalf("B's password worked in A: %d", st)
	}
	if st := w.ub.login(email, "password-for-A"); st != 401 {
		t.Fatalf("A's password worked in B: %d", st)
	}
	if st := w.ua.login(email, "password-for-A"); st != 200 {
		t.Fatalf("A login: %d", st)
	}
	if st := w.ub.login(email, "password-for-B"); st != 200 {
		t.Fatalf("B login: %d", st)
	}
	_, bodyA := w.ua.me()
	_, bodyB := w.ub.me()
	if userID(t, bodyA) == userID(t, bodyB) {
		t.Fatal("two applications returned the same user id")
	}
}

// A token from application A fails verification against application B.
func TestTokenFromOneApplicationFailsAgainstAnother(t *testing.T) {
	w := newTwoApps(t)
	ctx := context.Background()
	w.ua.signup("a@example.com", "password-1")
	w.ua.login("a@example.com", "password-1")
	w.ub.signup("b@example.com", "password-1")
	w.ub.login("b@example.com", "password-1")
	tokA, tokB := w.ua.token(), w.ub.token()
	now := w.clock.Now()

	claims, err := w.ts.Verify(ctx, w.a.ID, tokA, now)
	if err != nil {
		t.Fatalf("A's token against A: %v", err)
	}
	if claims.Issuer != w.a.Issuer || !claims.Audience.Contains(w.a.ID) {
		t.Fatalf("claims = %+v, application issuer %s", claims, w.a.Issuer)
	}
	if _, err := w.ts.Verify(ctx, w.b.ID, tokA, now); err == nil {
		t.Fatal("A's token verified against B")
	}
	if _, err := w.ts.Verify(ctx, w.a.ID, tokB, now); err == nil {
		t.Fatal("B's token verified against A")
	}

	// Verifying the way a customer backend does, with only a JWKS URL and an
	// issuer: A's token fails against B's published keys.
	_, jwksB, _ := w.call("GET", "/apps/"+w.b.ID+"/.well-known/jwks.json", "")
	var set auth.JWKS
	if err := json.Unmarshal([]byte(jwksB), &set); err != nil || len(set.Keys) == 0 {
		t.Fatalf("B's JWKS: %v %s", err, jwksB)
	}
	for _, k := range set.Keys {
		if strings.Contains(tokA, k.Kid) {
			t.Fatal("A's token mentions a key id from B's JWKS")
		}
	}
}

// A leaked publishable key must not open anything that needs a secret key.
func TestPublishableKeyCannotCallSecretKeyEndpoints(t *testing.T) {
	w := newTwoApps(t)
	pk, sk := w.a.PublishableKey, w.a.SecretKey
	if !auth.IsSecretKey(sk) {
		t.Fatalf("create did not return a secret key: %q", sk)
	}

	backend := []struct{ method, path string }{
		{"GET", "/v1/backend/users"},
		{"GET", "/v1/backend/users/" + "00000000-0000-4000-8000-000000000001"},
	}
	for _, ep := range backend {
		for name, hdr := range map[string][]string{
			"publishable key as bearer":   {"Authorization", "Bearer " + pk},
			"publishable key as X-header": {publishableKeyHeader, pk},
			"both":                        {"Authorization", "Bearer " + pk, publishableKeyHeader, pk},
			"nothing":                     nil,
			"junk bearer":                 {"Authorization", "Bearer sk_live_" + strings.Repeat("x", 43)},
			"basic auth":                  {"Authorization", "Basic " + sk},
			"developer token":             {"Authorization", "Bearer " + w.dev},
		} {
			st, body, _ := w.call(ep.method, ep.path, "", hdr...)
			if st != 401 || errCode(t, body) != "invalid_secret_key" {
				t.Errorf("%s %s with %s: %d %s", ep.method, ep.path, name, st, body)
			}
		}
	}

	// The secret key works there...
	if st, body, _ := w.call("GET", "/v1/backend/users", "", "Authorization", "Bearer "+sk); st != 200 {
		t.Fatalf("secret key refused: %d %s", st, body)
	}
	// ...but is not a publishable key: it cannot stand in for one on end-user routes.
	if st, body, _ := w.call("POST", "/v1/login", creds("x@example.com", "password-1"), publishableKeyHeader, sk); st != 401 || errCode(t, body) != "invalid_publishable_key" {
		t.Fatalf("secret key accepted as publishable: %d %s", st, body)
	}
	// And neither key opens the platform API.
	for _, tok := range []string{pk, sk} {
		if st, _, _ := w.call("GET", "/v1/platform/applications", "", "Authorization", "Bearer "+tok); st != 401 {
			t.Fatalf("platform API accepted %s…: %d", tok[:8], st)
		}
	}
}

func TestBackendSeesOnlyItsOwnApplicationsUsers(t *testing.T) {
	w := newTwoApps(t)
	w.ua.signup("shared@example.com", "password-1")
	w.ua.signup("only-a@example.com", "password-1")
	w.ub.signup("shared@example.com", "password-2")
	skA, skB := "Bearer "+w.a.SecretKey, "Bearer "+w.b.SecretKey

	_, body, _ := w.call("GET", "/v1/backend/users", "", "Authorization", skA)
	listA := decode[struct{ Users []backendUser }](t, body).Users
	_, body, _ = w.call("GET", "/v1/backend/users", "", "Authorization", skB)
	listB := decode[struct{ Users []backendUser }](t, body).Users
	if len(listA) != 2 || len(listB) != 1 {
		t.Fatalf("A sees %d users, B sees %d; want 2 and 1", len(listA), len(listB))
	}
	for _, a := range listA {
		for _, b := range listB {
			if a.ID == b.ID {
				t.Fatal("applications share a user")
			}
		}
	}

	// Fetching one user: own is 200, the other application's is 404.
	if st, _, _ := w.call("GET", "/v1/backend/users/"+listA[0].ID, "", "Authorization", skA); st != 200 {
		t.Fatalf("own user: %d", st)
	}
	if st, body, _ := w.call("GET", "/v1/backend/users/"+listA[0].ID, "", "Authorization", skB); st != 404 {
		t.Fatalf("B read A's user: %d %s", st, body)
	}
	// The password hash never leaves.
	_, body, _ = w.call("GET", "/v1/backend/users/"+listA[0].ID, "", "Authorization", skA)
	if strings.Contains(body, "argon2") || strings.Contains(body, "password") {
		t.Fatalf("backend response leaks credentials: %s", body)
	}

	// Pagination and its validation.
	_, body, _ = w.call("GET", "/v1/backend/users?limit=1&offset=1", "", "Authorization", skA)
	if got := decode[struct{ Users []backendUser }](t, body).Users; len(got) != 1 || got[0].ID != listA[1].ID {
		t.Fatalf("offset page = %+v", got)
	}
	for _, q := range []string{"limit=0", "limit=101", "limit=x", "offset=-1"} {
		if st, _, _ := w.call("GET", "/v1/backend/users?"+q, "", "Authorization", skA); st != 422 {
			t.Errorf("?%s: %d, want 422", q, st)
		}
	}
}

// --- application resolution -------------------------------------------------

func TestUnknownPublishableKeyIsRejected(t *testing.T) {
	w := newTwoApps(t)
	unknown, _ := auth.NewPublishableKey()
	routes := []struct{ method, path, body string }{
		{"POST", "/v1/signup", creds("x@example.com", "password-1")},
		{"POST", "/v1/login", creds("x@example.com", "password-1")},
		{"GET", "/v1/me", ""},
		{"POST", "/v1/logout", ""},
		{"GET", "/v1/sessions", ""},
		{"DELETE", "/v1/sessions/x", ""},
		{"POST", "/v1/sessions/x/token", ""},
	}
	for name, hdr := range map[string][]string{
		"missing":   nil,
		"unknown":   {publishableKeyHeader, unknown},
		"malformed": {publishableKeyHeader, "pk_live_short"},
		"empty":     {publishableKeyHeader, ""},
		"sql":       {publishableKeyHeader, "pk_live_' OR '1'='1"},
	} {
		for _, rt := range routes {
			st, body, _ := w.call(rt.method, rt.path, rt.body, hdr...)
			if st != 401 || errCode(t, body) != "invalid_publishable_key" {
				t.Errorf("%s key, %s %s: %d %s", name, rt.method, rt.path, st, body)
			}
		}
	}
	// Nothing was created along the way.
	for _, a := range []*actor{w.ua, w.ub} {
		_, body, _ := w.call("GET", "/v1/backend/users", "", "Authorization", "Bearer "+map[*actor]string{w.ua: w.a.SecretKey, w.ub: w.b.SecretKey}[a])
		if n := len(decode[struct{ Users []backendUser }](t, body).Users); n != 0 {
			t.Fatalf("%d users created by rejected requests", n)
		}
	}
}

func TestSessionCookiesAreBoundToTheirApplication(t *testing.T) {
	w := newTwoApps(t)
	w.ua.signup("alice@example.com", "password-1")
	w.ua.login("alice@example.com", "password-1")
	w.ub.signup("alice@example.com", "password-1")

	if st, _ := w.ua.me(); st != 200 {
		t.Fatalf("own session: %d", st)
	}
	u, _ := url.Parse(w.url)
	var cookie *nethttp.Cookie
	for _, c := range w.ua.c.Jar.Cookies(u) {
		cookie = c
	}
	if cookie == nil || cookie.Name != sessionCookiePrefix+auth.CookieSuffix(w.a.PublishableKey) {
		t.Fatalf("cookie = %+v", cookie)
	}

	// A's browser, B's publishable key: the cookie is for another application.
	if st, _, _ := send(t, w.ua.c, w.url+"/v1/me", "GET", "", publishableKeyHeader, w.b.PublishableKey); st != 401 {
		t.Fatalf("A's session accepted by B: %d", st)
	}
	// Even renamed to B's cookie name, A's session token resolves to nothing in B.
	forged := sessionCookiePrefix + auth.CookieSuffix(w.b.PublishableKey) + "=" + cookie.Value
	if st, _, _ := w.call("GET", "/v1/me", "", publishableKeyHeader, w.b.PublishableKey, "Cookie", forged); st != 401 {
		t.Fatalf("A's session token accepted as B's: %d", st)
	}
	// Sanity: the same raw token under A's own name does work.
	if st, _, _ := w.call("GET", "/v1/me", "", publishableKeyHeader, w.a.PublishableKey, "Cookie", cookie.Name+"="+cookie.Value); st != 200 {
		t.Fatalf("control request failed: %d", st)
	}

	// One browser can hold sessions for both applications at once.
	both := w.env.actor("")
	for _, app := range []applicationResponse{w.a, w.b} {
		both.pk = app.PublishableKey
		both.signup("both@example.com", "password-1")
		if st := both.login("both@example.com", "password-1"); st != 200 {
			t.Fatalf("login in %s: %d", app.Name, st)
		}
	}
	for _, app := range []applicationResponse{w.a, w.b} {
		both.pk = app.PublishableKey
		if st, _ := both.me(); st != 200 {
			t.Fatalf("%s session lost after logging in to the other application: %d", app.Name, st)
		}
	}
}

func TestSecretKeyIsShownOnce(t *testing.T) {
	w := newTwoApps(t)
	if !strings.HasSuffix(w.a.SecretKey, w.a.SecretKeyLast4) || w.a.SecretKey == "" {
		t.Fatalf("create response: %+v", w.a)
	}
	for _, path := range []string{"/v1/platform/applications/" + w.a.ID, "/v1/platform/applications"} {
		_, body, _ := w.call("GET", path, "", bearerHdr(w.dev)...)
		if strings.Contains(body, w.a.SecretKey) || strings.Contains(body, `"secret_key":`) {
			t.Fatalf("GET %s returned the secret key: %s", path, body)
		}
		if !strings.Contains(body, w.a.SecretKeyLast4) {
			t.Fatalf("GET %s lacks last4", path)
		}
	}
	if w.a.Issuer != w.url+"/apps/"+w.a.ID || w.a.JWKSURL != w.a.Issuer+"/.well-known/jwks.json" {
		t.Fatalf("issuer/jwks_url = %s %s", w.a.Issuer, w.a.JWKSURL)
	}
	if w.a.PublishableKey == w.b.PublishableKey || w.a.SecretKey == w.b.SecretKey || w.a.Issuer == w.b.Issuer {
		t.Fatal("two applications share credentials")
	}
}

func TestRollSecretKey(t *testing.T) {
	w := newTwoApps(t)
	oldKey := w.a.SecretKey
	st, body, hdr := w.call("POST", "/v1/platform/applications/"+w.a.ID+"/secret-key/roll", "", bearerHdr(w.dev)...)
	if st != 200 {
		t.Fatalf("roll: %d %s", st, body)
	}
	if hdr.Get("Cache-Control") != "no-store" {
		t.Fatal("rolled secret key response is cacheable")
	}
	rolled := decode[applicationResponse](t, body)
	if rolled.SecretKey == "" || rolled.SecretKey == oldKey || !strings.HasSuffix(rolled.SecretKey, rolled.SecretKeyLast4) {
		t.Fatalf("rolled = %+v", rolled)
	}
	if st, _, _ := w.call("GET", "/v1/backend/users", "", "Authorization", "Bearer "+oldKey); st != 401 {
		t.Fatalf("old secret key still works: %d", st)
	}
	if st, _, _ := w.call("GET", "/v1/backend/users", "", "Authorization", "Bearer "+rolled.SecretKey); st != 200 {
		t.Fatalf("new secret key refused: %d", st)
	}
	// B's key is untouched.
	if st, _, _ := w.call("GET", "/v1/backend/users", "", "Authorization", "Bearer "+w.b.SecretKey); st != 200 {
		t.Fatalf("rolling A broke B: %d", st)
	}
}

// --- per-application settings ----------------------------------------------

func (w *twoApps) patch(app applicationResponse, body string) (int, string) {
	st, resp, _ := w.call("PATCH", "/v1/platform/applications/"+app.ID, body, bearerHdr(w.dev)...)
	return st, resp
}

func TestSignupCanBeDisabledPerApplication(t *testing.T) {
	w := newTwoApps(t)
	w.ua.signup("early@example.com", "password-1")
	if st, body := w.patch(w.a, `{"signup_enabled":false}`); st != 200 {
		t.Fatalf("patch: %d %s", st, body)
	}
	st, body, _ := w.ua.call("POST", "/v1/signup", creds("late@example.com", "password-1"))
	if st != 403 || errCode(t, body) != "signup_disabled" {
		t.Fatalf("signup while disabled: %d %s", st, body)
	}
	if st := w.ua.login("early@example.com", "password-1"); st != 200 {
		t.Fatalf("existing user cannot log in: %d", st)
	}
	if st := w.ub.signup("late@example.com", "password-1"); st != 201 {
		t.Fatalf("B affected by A's setting: %d", st)
	}
	w.patch(w.a, `{"signup_enabled":true}`)
	if st := w.ua.signup("late@example.com", "password-1"); st != 201 {
		t.Fatalf("signup after re-enabling: %d", st)
	}
}

func TestSessionLifetimeIsPerApplication(t *testing.T) {
	w := newTwoApps(t)
	// A: 2 hour sessions, 1 hour idle timeout. B keeps the defaults (30 days / 7 days).
	if st, body := w.patch(w.a, `{"session_lifetime_seconds":7200,"session_idle_timeout_seconds":3600}`); st != 200 {
		t.Fatalf("patch: %d %s", st, body)
	}
	for _, a := range []*actor{w.ua, w.ub} {
		a.signup("c@example.com", "password-1")
	}
	_, _, hdrA := w.ua.call("POST", "/v1/login", creds("c@example.com", "password-1"))
	_, _, hdrB := w.ub.call("POST", "/v1/login", creds("c@example.com", "password-1"))
	maxAge := func(h nethttp.Header) int {
		for _, c := range (&nethttp.Response{Header: h}).Cookies() {
			return c.MaxAge
		}
		return 0
	}
	if got := maxAge(hdrA); got != 7200 {
		t.Fatalf("A cookie Max-Age = %d, want 7200", got)
	}
	if got := maxAge(hdrB); got != 30*24*3600 {
		t.Fatalf("B cookie Max-Age = %d, want 30 days", got)
	}

	// Idle timeout: after 61 idle minutes A's session is gone, B's is not.
	w.clock.Advance(61 * time.Minute)
	if st, _ := w.ua.me(); st != 401 {
		t.Fatalf("A session survived its idle timeout: %d", st)
	}
	if st, _ := w.ub.me(); st != 200 {
		t.Fatalf("B session expired with A's settings: %d", st)
	}

	// Absolute lifetime: staying active does not extend A past 2 hours.
	w.ua.login("c@example.com", "password-1")
	for i := 0; i < 2; i++ {
		w.clock.Advance(50 * time.Minute)
		if st, _ := w.ua.me(); st != 200 {
			t.Fatalf("active session expired early at step %d: %d", i, st)
		}
	}
	w.clock.Advance(30 * time.Minute) // 130 minutes after login
	if st, _ := w.ua.me(); st != 401 {
		t.Fatalf("session outlived its absolute lifetime: %d", st)
	}
}

func TestUpdateApplicationValidation(t *testing.T) {
	w := newTwoApps(t)
	long := strings.Repeat("n", 101)
	for name, body := range map[string]string{
		"empty name":            `{"name":"  "}`,
		"long name":             `{"name":"` + long + `"}`,
		"origin with path":      `{"allowed_origins":["https://x.com/app"]}`,
		"origin with wildcard":  `{"allowed_origins":["https://*.x.com"]}`,
		"origin wrong scheme":   `{"allowed_origins":["ftp://x.com"]}`,
		"javascript origin":     `{"allowed_origins":["javascript:alert(1)"]}`,
		"origin with query":     `{"allowed_origins":["https://x.com?a=1"]}`,
		"origin with userinfo":  `{"allowed_origins":["https://u:p@x.com"]}`,
		"bare host":             `{"allowed_origins":["x.com"]}`,
		"too many origins":      `{"allowed_origins":["` + strings.Join(manyOrigins(21), `","`) + `"]}`,
		"lifetime too short":    `{"session_lifetime_seconds":60}`,
		"lifetime too long":     `{"session_lifetime_seconds":99999999}`,
		"idle too short":        `{"session_idle_timeout_seconds":10}`,
		"idle exceeds lifetime": `{"session_lifetime_seconds":3600,"session_idle_timeout_seconds":7200}`,
		"lifetime below idle":   `{"session_lifetime_seconds":3600}`, // existing idle is 7 days
	} {
		if st, resp := w.patch(w.a, body); st != 422 || errCode(t, resp) != "validation_error" {
			t.Errorf("%s: %d %s", name, st, resp)
		}
	}
	for name, body := range map[string]string{
		"unknown field": `{"nope":1}`,
		"wrong type":    `{"signup_enabled":"yes"}`,
		"not json":      `{`,
	} {
		if st, _ := w.patch(w.a, body); st != 400 {
			t.Errorf("%s: %d, want 400", name, st)
		}
	}
	// None of the rejected requests changed anything.
	_, body, _ := w.call("GET", "/v1/platform/applications/"+w.a.ID, "", bearerHdr(w.dev)...)
	got := decode[applicationResponse](t, body)
	if got.Name != "App A" || got.Settings.SessionLifetimeSec != 30*24*3600 || len(got.Settings.AllowedOrigins) != 0 {
		t.Fatalf("a rejected update changed the application: %+v", got)
	}

	// A valid update normalises and de-duplicates origins and leaves other fields alone.
	st, resp := w.patch(w.a, `{"name":" Renamed ","allowed_origins":["HTTPS://Example.com/","https://example.com","http://localhost:3000"]}`)
	if st != 200 {
		t.Fatalf("valid update: %d %s", st, resp)
	}
	got = decode[applicationResponse](t, resp)
	if got.Name != "Renamed" || strings.Join(got.Settings.AllowedOrigins, ",") != "https://example.com,http://localhost:3000" ||
		got.Settings.SessionLifetimeSec != 30*24*3600 || !got.Settings.SignupEnabled {
		t.Fatalf("after update: %+v", got)
	}
	// Clearing the list is allowed and gives [] rather than null.
	_, resp = w.patch(w.a, `{"allowed_origins":[]}`)
	if !strings.Contains(resp, `"allowed_origins":[]`) {
		t.Fatalf("cleared origins: %s", resp)
	}
}

func manyOrigins(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "https://site" + string(rune('a'+i)) + ".example"
	}
	return out
}

// --- ownership ---------------------------------------------------------------

func TestDevelopersCannotTouchEachOthersApplications(t *testing.T) {
	w := newTwoApps(t)
	other := w.env.developer("other@example.com")
	h := bearerHdr(other)
	base := "/v1/platform/applications/" + w.a.ID

	for _, ep := range []struct{ method, path, body string }{
		{"GET", base, ""},
		{"PATCH", base, `{"name":"stolen"}`},
		{"POST", base + "/secret-key/roll", ""},
		{"POST", base + "/signing-keys/rotate", ""},
		{"GET", "/v1/platform/applications/not-a-uuid", ""},
	} {
		if st, body, _ := w.call(ep.method, ep.path, ep.body, h...); st != 404 || errCode(t, body) != "not_found" {
			t.Errorf("%s %s as another developer: %d %s", ep.method, ep.path, st, body)
		}
	}
	_, body, _ := w.call("GET", "/v1/platform/applications", "", h...)
	if n := len(decode[struct{ Applications []applicationResponse }](t, body).Applications); n != 0 {
		t.Fatalf("other developer lists %d applications", n)
	}
	// And nothing changed for the owner.
	_, body, _ = w.call("GET", base, "", bearerHdr(w.dev)...)
	if got := decode[applicationResponse](t, body); got.Name != "App A" {
		t.Fatalf("application changed: %+v", got)
	}
	if st, _, _ := w.call("GET", "/v1/backend/users", "", "Authorization", "Bearer "+w.a.SecretKey); st != 200 {
		t.Fatal("secret key was rolled by another developer")
	}
}

func TestPlatformAuth(t *testing.T) {
	e := newEnv(t)
	tok := e.developer("dev@example.com")

	if st, _, _ := e.call("POST", "/v1/platform/signup", creds("DEV@example.com", "dev-password-1")); st != 409 {
		t.Fatalf("duplicate developer (different case): %d", st)
	}
	if st, _, _ := e.call("POST", "/v1/platform/signup", creds("new@example.com", "short")); st != 422 {
		t.Fatalf("weak password: %d", st)
	}
	st1, b1, _ := e.call("POST", "/v1/platform/login", creds("dev@example.com", "wrong-password"))
	st2, b2, _ := e.call("POST", "/v1/platform/login", creds("nobody@example.com", "wrong-password"))
	if st1 != 401 || st1 != st2 || b1 != b2 {
		t.Fatalf("login errors differ: %d %s / %d %s", st1, b1, st2, b2)
	}
	for _, hdr := range [][]string{nil, {"Authorization", "Bearer dvt_" + strings.Repeat("a", 43)}, {"Authorization", "Bearer junk"}} {
		if st, _, _ := e.call("GET", "/v1/platform/me", "", hdr...); st != 401 {
			t.Fatalf("platform /me with %v: %d", hdr, st)
		}
	}
	if st, body, _ := e.call("GET", "/v1/platform/me", "", bearerHdr(tok)...); st != 200 || !strings.Contains(body, "dev@example.com") {
		t.Fatalf("me: %d %s", st, body)
	}
	// A developer token is not an end-user credential.
	if st, _, _ := e.call("GET", "/v1/me", "", publishableKeyHeader, tok); st != 401 {
		t.Fatalf("developer token accepted as publishable key: %d", st)
	}

	// Logout revokes the token.
	if st, _, _ := e.call("POST", "/v1/platform/logout", "", bearerHdr(tok)...); st != 204 {
		t.Fatalf("logout: %d", st)
	}
	if st, _, _ := e.call("GET", "/v1/platform/me", "", bearerHdr(tok)...); st != 401 {
		t.Fatalf("token works after logout: %d", st)
	}

	// Tokens expire.
	_, body, _ := e.call("POST", "/v1/platform/login", creds("dev@example.com", "dev-password-1"))
	fresh := decode[struct{ Token string }](t, body).Token
	e.clock.Advance(auth.DeveloperSessionTTL + time.Minute)
	if st, _, _ := e.call("GET", "/v1/platform/me", "", bearerHdr(fresh)...); st != 401 {
		t.Fatalf("expired developer token accepted: %d", st)
	}
}

func TestCreateApplicationValidation(t *testing.T) {
	e := newEnv(t)
	tok := e.developer("dev@example.com")
	for _, body := range []string{`{}`, `{"name":""}`, `{"name":"` + strings.Repeat("x", 101) + `"}`} {
		if st, _, _ := e.call("POST", "/v1/platform/applications", body, bearerHdr(tok)...); st != 422 {
			t.Errorf("%s: %d, want 422", body, st)
		}
	}
	if st, _, _ := e.call("POST", "/v1/platform/applications", `{"name":"x","extra":1}`, bearerHdr(tok)...); st != 400 {
		t.Errorf("unknown field: %d", st)
	}
	if st, _, _ := e.call("POST", "/v1/platform/applications", `{"name":"x"}`); st != 401 {
		t.Errorf("no token: %d", st)
	}
}

// --- signing keys and JWKS ---------------------------------------------------

func TestJWKSIsPerApplication(t *testing.T) {
	w := newTwoApps(t)
	fetch := func(id string) (int, string, nethttp.Header) {
		return w.call("GET", "/apps/"+id+"/.well-known/jwks.json", "")
	}
	st, bodyA, hdr := fetch(w.a.ID)
	if st != 200 || hdr.Get("Cache-Control") != "public, max-age=300" {
		t.Fatalf("A: %d %v", st, hdr)
	}
	_, bodyB, _ := fetch(w.b.ID)
	setA, setB := decode[auth.JWKS](t, bodyA), decode[auth.JWKS](t, bodyB)
	if len(setA.Keys) != 1 || len(setB.Keys) != 1 || setA.Keys[0].Kid == setB.Keys[0].Kid || setA.Keys[0].X == setB.Keys[0].X {
		t.Fatalf("JWKS not separate: %s / %s", bodyA, bodyB)
	}
	if strings.Contains(bodyA, `"d"`) {
		t.Fatalf("JWKS leaks a private component: %s", bodyA)
	}
	if st, body, _ := fetch("00000000-0000-4000-8000-00000000ffff"); st != 404 || errCode(t, body) != "not_found" {
		t.Fatalf("unknown application: %d %s", st, body)
	}
	if st, _, _ := fetch("not-a-uuid"); st != 404 {
		t.Fatalf("malformed application id: %d", st)
	}
	// The root-level JWKS from earlier stages is gone: there is no global key set.
	if st, _, _ := w.call("GET", "/.well-known/jwks.json", ""); st != 404 {
		t.Fatalf("global JWKS still served: %d", st)
	}
}

func TestRotateSigningKeyAffectsOnlyThatApplication(t *testing.T) {
	w := newTwoApps(t)
	w.ua.signup("a@example.com", "password-1")
	w.ua.login("a@example.com", "password-1")
	before := w.ua.token()
	_, jb, _ := w.call("GET", "/apps/"+w.b.ID+"/.well-known/jwks.json", "")

	st, body, _ := w.call("POST", "/v1/platform/applications/"+w.a.ID+"/signing-keys/rotate", "", bearerHdr(w.dev)...)
	if st != 200 {
		t.Fatalf("rotate: %d %s", st, body)
	}
	res := decode[struct {
		Kid        string    `json:"kid"`
		ActiveFrom time.Time `json:"active_from"`
	}](t, body)
	if want := w.clock.Now().Add(auth.KeyActivationDelay); !res.ActiveFrom.Equal(want) {
		t.Fatalf("active_from = %v, want %v", res.ActiveFrom, want)
	}

	_, ja, _ := w.call("GET", "/apps/"+w.a.ID+"/.well-known/jwks.json", "")
	setA := decode[auth.JWKS](t, ja)
	if len(setA.Keys) != 2 || setA.Keys[0].Kid != res.Kid {
		t.Fatalf("A's JWKS after rotation: %s", ja)
	}
	_, jb2, _ := w.call("GET", "/apps/"+w.b.ID+"/.well-known/jwks.json", "")
	if jb != jb2 {
		t.Fatalf("rotating A changed B's JWKS:\n%s\n%s", jb, jb2)
	}

	// Tokens issued before the switch still verify; after it the new key signs.
	if _, err := w.ts.Verify(context.Background(), w.a.ID, before, w.clock.Now()); err != nil {
		t.Fatalf("old token after rotation: %v", err)
	}
	w.clock.Advance(auth.KeyActivationDelay + time.Second)
	w.ua.login("a@example.com", "password-1")
	after := w.ua.token()
	if kidOf(t, after) != res.Kid {
		t.Fatalf("token signed with %s, want the rotated-in key %s", kidOf(t, after), res.Kid)
	}
}

func kidOf(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var h struct{ Kid string }
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	return h.Kid
}
