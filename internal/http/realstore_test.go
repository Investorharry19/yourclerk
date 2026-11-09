package http

import (
	"context"
	"errors"
	"fmt"
	appmail "github.com/Investorharry19/yourclerk/internal/mail"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"sync"
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
	e, db, ts := newRealEnv(t, ctx, dbURL)
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

// newRealEnv starts the server on the real Postgres store, with a real clock.
func newRealEnv(t *testing.T, ctx context.Context, dbURL string) (*env, *store.Store, *auth.TokenService) {
	t.Helper()
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
	e.sealer, err = auth.NewSealer("real-store-secret-real-store-secret-1")
	if err != nil {
		t.Fatal(err)
	}
	e.srv.Config.Handler = NewServer(Deps{
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), DB: db,
		Registry: db, Developers: db, Apps: db, Tenants: db, Tokens: ts,
		Email:   &EmailDeps{Sealer: e.sealer, WebURL: testWebURL},
		Options: Options{Now: time.Now, EnableDocs: true},
	}).Handler()
	e.srv.Start()
	t.Cleanup(e.srv.Close)
	return e, db, ts
}

// TestRealStoreEmailFlow runs the Stage 5 pass criteria end to end on Postgres:
// the real outbox, the real worker, and a mail provider that fails once.
func TestRealStoreEmailFlow(t *testing.T) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	e, db, _ := newRealEnv(t, ctx, dbURL)
	devEmail := fmt.Sprintf("mail-%d@example.com", time.Now().UnixNano())
	dev := e.developer(devEmail)
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), "DELETE FROM developers WHERE email = $1", devEmail)
	})
	app := e.createApp(dev, "Mail App")
	a := e.actor(app.PublishableKey)
	other := e.actor(app.PublishableKey)

	// A worker over the real queue whose provider fails on the first send.
	clk := newTestClock()
	clk.Advance(2 * time.Second) // rows are due as of the server's real "now"
	provider := &captureMailer{failFirst: 1}
	worker := &appmail.Worker{Outbox: db, Mailer: provider, Sealer: e.sealer, From: "a@example.com",
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: clk.Now}
	drain := func() { // process until nothing of ours is left due
		for i := 0; i < 3; i++ {
			if _, _, err := worker.ProcessOnce(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}

	// Signup succeeds even though the first delivery attempt will fail.
	const email = "mailed@example.com"
	if st := a.signup(email, pw1); st != 201 {
		t.Fatalf("signup: %d", st)
	}
	drain()
	if len(provider.sent(email)) != 0 {
		t.Fatal("delivered despite the provider failing")
	}
	clk.Advance(31 * time.Second) // past the first backoff (30s)
	drain()
	sent := provider.sent(email)
	if len(sent) != 1 {
		t.Fatalf("after the retry %d emails were delivered, want 1", len(sent))
	}
	verify := linkToken(t, sent[0])

	// The link works once.
	if st, body := a.post("/v1/verify-email", tokenBodyJSON(verify)); st != 200 {
		t.Fatalf("verify: %d %s", st, body)
	}
	if st, _ := a.post("/v1/verify-email", tokenBodyJSON(verify)); st != 400 {
		t.Fatalf("verify link worked twice: %d", st)
	}
	var plen int
	_ = db.Pool.QueryRow(ctx, `SELECT coalesce(sum(length(payload)),0) FROM email_outbox o JOIN applications a ON a.id = o.application_id
		WHERE a.publishable_key = $1 AND o.status = 'sent'`, app.PublishableKey).Scan(&plen)
	if plen != 0 {
		t.Fatalf("sent emails still hold %d bytes of payload", plen)
	}

	// Reset: identical forgot responses, a working link, and old sessions die.
	a.login(email, pw1)
	other.login(email, pw1)
	st1, b1 := a.post("/v1/password/forgot", `{"email":"`+email+`"}`)
	st2, b2 := a.post("/v1/password/forgot", `{"email":"nobody@example.com"}`)
	if st1 != 202 || st1 != st2 || b1 != b2 {
		t.Fatalf("forgot responses differ: %d %q / %d %q", st1, b1, st2, b2)
	}
	drain()
	sent = provider.sent(email)
	if len(sent) != 2 {
		t.Fatalf("%d emails delivered, want verification + reset", len(sent))
	}
	reset := linkToken(t, sent[1])
	if st, body := a.post("/v1/password/reset", resetBodyJSON(reset, pw2)); st != 204 {
		t.Fatalf("reset: %d %s", st, body)
	}
	if st, _ := other.me(); st != 401 {
		t.Fatalf("an older session survived the reset: %d", st)
	}
	if st := a.login(email, pw1); st != 401 {
		t.Fatalf("old password works: %d", st)
	}
	if st := a.login(email, pw2); st != 200 {
		t.Fatalf("new password: %d", st)
	}
	if st, _ := a.post("/v1/password/reset", resetBodyJSON(reset, "third-password-3")); st != 400 {
		t.Fatalf("reset link worked twice: %d", st)
	}
}

// captureMailer records deliveries and fails the first failFirst sends.
type captureMailer struct {
	mu        sync.Mutex
	failFirst int
	msgs      []appmail.Message
}

func (c *captureMailer) Send(_ context.Context, _ string, m appmail.Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failFirst > 0 {
		c.failFirst--
		return errors.New("provider down")
	}
	c.msgs = append(c.msgs, m)
	return nil
}

func (c *captureMailer) sent(to string) (out []appmail.Message) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, m := range c.msgs {
		if m.To == to {
			out = append(out, m)
		}
	}
	return
}
