package http

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/Investorharry19/yourclerk/internal/auth"
	"github.com/Investorharry19/yourclerk/internal/store"
)

// TestRealStoreEndToEnd runs the Stage 4 pass criteria through the real
// Postgres store, so the in-memory fakes used elsewhere cannot drift from the
// SQL unnoticed. Skipped without TEST_DATABASE_URL.
func TestRealStoreEndToEnd(t *testing.T) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	db, err := store.New(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)

	e := &env{t: t, clock: newTestClock()}
	e.srv = httptest.NewUnstartedServer(nil)
	e.url = "http://" + e.srv.Listener.Addr().String()
	ts, err := auth.NewTokenService(db, "real-store-secret-real-store-secret-1", e.url, 0)
	if err != nil {
		t.Fatal(err)
	}
	e.ts = ts
	e.srv.Config.Handler = NewServer(Deps{
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), DB: db,
		Registry: db, Developers: db, Apps: db, Tenants: db, Tokens: ts,
		Options: Options{Now: time.Now, EnableDocs: true},
	}).Handler()
	e.srv.Start()
	t.Cleanup(e.srv.Close)

	devEmail := fmt.Sprintf("e2e-%d@example.com", time.Now().UnixNano())
	dev := e.developer(devEmail)
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), "DELETE FROM developers WHERE email = $1", devEmail)
	})
	a, b := e.createApp(dev, "A"), e.createApp(dev, "B")
	ua, ub := e.actor(a.PublishableKey), e.actor(b.PublishableKey)

	// Same email in both applications with different passwords.
	const email = "alice@example.com"
	if ua.signup(email, "password-for-A") != 201 || ub.signup(email, "password-for-B") != 201 {
		t.Fatal("signup in both applications failed")
	}
	if ua.signup(email, "x-password-1") != 409 {
		t.Fatal("duplicate inside one application accepted")
	}
	if ua.login(email, "password-for-B") != 401 || ub.login(email, "password-for-A") != 401 {
		t.Fatal("a password worked in the wrong application")
	}
	if ua.login(email, "password-for-A") != 200 || ub.login(email, "password-for-B") != 200 {
		t.Fatal("login failed in an application")
	}

	// Tokens: A's token fails against B.
	tokA := ua.token()
	if _, err := ts.Verify(ctx, a.ID, tokA, time.Now()); err != nil {
		t.Fatalf("A's token against A: %v", err)
	}
	if _, err := ts.Verify(ctx, b.ID, tokA, time.Now()); err == nil {
		t.Fatal("A's token verified against B")
	}

	// A's cookie is useless to B.
	if st, _, _ := send(t, ua.c, e.url+"/v1/me", "GET", "", publishableKeyHeader, b.PublishableKey); st != 401 {
		t.Fatalf("A's session accepted by B: %d", st)
	}

	// Publishable key vs secret key; backend scoping.
	if st, _, _ := e.call("GET", "/v1/backend/users", "", "Authorization", "Bearer "+a.PublishableKey); st != 401 {
		t.Fatalf("publishable key accepted on a secret-key endpoint: %d", st)
	}
	_, body, _ := e.call("GET", "/v1/backend/users", "", "Authorization", "Bearer "+a.SecretKey)
	if got := decode[struct{ Users []backendUser }](t, body).Users; len(got) != 1 || got[0].Email != email {
		t.Fatalf("A's backend sees %+v", got)
	}
	idA := decode[struct{ Users []backendUser }](t, body).Users[0].ID
	if st, _, _ := e.call("GET", "/v1/backend/users/"+idA, "", "Authorization", "Bearer "+b.SecretKey); st != 404 {
		t.Fatalf("B's secret key read A's user: %d", st)
	}

	// Settings and rotation go through the database too.
	if st, body := (&twoApps{env: e, dev: dev}).patch(a, `{"signup_enabled":false,"allowed_origins":["https://a.example"]}`); st != 200 {
		t.Fatalf("patch: %d %s", st, body)
	}
	if st, _, _ := ua.call("POST", "/v1/signup", creds("late@example.com", "password-1")); st != 403 {
		t.Fatalf("signup while disabled: %d", st)
	}
	if st, _, _ := e.call("POST", "/v1/platform/applications/"+a.ID+"/signing-keys/rotate", "", bearerHdr(dev)...); st != 200 {
		t.Fatalf("rotate: %d", st)
	}
	_, ja, _ := e.call("GET", "/apps/"+a.ID+"/.well-known/jwks.json", "")
	_, jb, _ := e.call("GET", "/apps/"+b.ID+"/.well-known/jwks.json", "")
	if n := len(decode[auth.JWKS](t, ja).Keys); n != 2 {
		t.Fatalf("A has %d keys after rotation", n)
	}
	if n := len(decode[auth.JWKS](t, jb).Keys); n != 1 {
		t.Fatalf("B has %d keys", n)
	}
}
