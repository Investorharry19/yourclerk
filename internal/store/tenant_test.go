package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Investorharry19/yourclerk/internal/auth"
)

var now0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

type world struct {
	s        *Store
	dev      Developer
	a, b     Application
	ctx      context.Context
	ta, tb   Tenant
	skA, skB string
}

// newWorld needs a real Postgres with migrations applied; skipped without TEST_DATABASE_URL.
func newWorld(t *testing.T) *world {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	s, err := New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	dev, err := s.CreateDeveloper(ctx, "dev-"+suffix+"@example.com", "hash")
	if err != nil {
		t.Fatalf("CreateDeveloper: %v (did you run migrations?)", err)
	}
	t.Cleanup(func() { // cascades to applications, users, sessions, signing keys
		_, _ = s.Pool.Exec(context.Background(), "DELETE FROM developers WHERE id::text = $1", dev.ID)
	})
	mk := func(name string) (Application, string) {
		pk, _ := auth.NewPublishableKey()
		sk, h, l4, _ := auth.NewSecretKey()
		a, err := s.CreateApplication(ctx, NewApplication{DeveloperID: dev.ID, Name: name, PublishableKey: pk, SecretKeyHash: h, SecretKeyLast4: l4})
		if err != nil {
			t.Fatal(err)
		}
		return a, sk
	}
	w := &world{s: s, dev: dev, ctx: ctx}
	w.a, w.skA = mk("A")
	w.b, w.skB = mk("B")
	w.ta, w.tb = s.ForApp(w.a.ID), s.ForApp(w.b.ID)
	return w
}

func TestSameEmailInTwoApplications(t *testing.T) {
	w := newWorld(t)
	ua, err := w.ta.CreateUser(w.ctx, "same@example.com", "hash-A")
	if err != nil {
		t.Fatal(err)
	}
	ub, err := w.tb.CreateUser(w.ctx, "same@example.com", "hash-B")
	if err != nil {
		t.Fatalf("same email in a second application refused: %v", err)
	}
	if ua.ID == ub.ID || ua.PasswordHash == ub.PasswordHash {
		t.Fatal("the two applications share a user")
	}
	if _, err := w.ta.CreateUser(w.ctx, "same@example.com", "x"); !errors.Is(err, ErrEmailTaken) {
		t.Fatalf("duplicate inside one application: %v", err)
	}
	if _, err := w.ta.CreateUser(w.ctx, "UPPER@example.com", "x"); err == nil || errors.Is(err, ErrEmailTaken) {
		t.Fatalf("upper-case email: %v, want a constraint error", err)
	}
	got, _ := w.tb.GetUserByEmail(w.ctx, "same@example.com")
	if got.PasswordHash != "hash-B" {
		t.Fatalf("B read %q", got.PasswordHash)
	}
}

func TestUsersAreInvisibleAcrossApplications(t *testing.T) {
	w := newWorld(t)
	ua, _ := w.ta.CreateUser(w.ctx, "only-a@example.com", "h")

	if _, err := w.tb.GetUserByEmail(w.ctx, "only-a@example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("B found A's user by email: %v", err)
	}
	if _, err := w.tb.GetUserByID(w.ctx, ua.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("B found A's user by id: %v", err)
	}
	if got, err := w.ta.GetUserByID(w.ctx, ua.ID); err != nil || got.ID != ua.ID {
		t.Fatalf("A cannot read its own user: %v", err)
	}
	if _, err := w.ta.GetUserByID(w.ctx, "not-a-uuid"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("malformed id: %v", err)
	}
	if l, _ := w.tb.ListUsers(w.ctx, 50, 0); len(l) != 0 {
		t.Fatalf("B lists %d of A's users", len(l))
	}
	for i := 0; i < 3; i++ {
		_, _ = w.ta.CreateUser(w.ctx, fmt.Sprintf("u%d@example.com", i), "h")
	}
	l, _ := w.ta.ListUsers(w.ctx, 2, 0)
	l2, _ := w.ta.ListUsers(w.ctx, 2, 2)
	if len(l) != 2 || len(l2) != 2 || l[0].ID == l2[0].ID {
		t.Fatalf("pagination: %d %d", len(l), len(l2))
	}
}

func TestSessionsAreInvisibleAcrossApplications(t *testing.T) {
	w := newWorld(t)
	ua, _ := w.ta.CreateUser(w.ctx, "s@example.com", "h")
	ub, _ := w.tb.CreateUser(w.ctx, "s@example.com", "h")
	exp := now0.Add(24 * time.Hour)
	idle := now0.Add(-time.Hour)

	tok, hash, _ := auth.NewSessionToken()
	_ = tok
	sess, err := w.ta.CreateSession(w.ctx, ua.ID, hash, "ua", "1.1.1.1", now0, exp)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := w.ta.GetLiveSession(w.ctx, hash, now0, idle); err != nil {
		t.Fatalf("own session: %v", err)
	}
	if _, _, err := w.tb.GetLiveSession(w.ctx, hash, now0, idle); !errors.Is(err, ErrNotFound) {
		t.Fatalf("B resolved A's session token: %v", err)
	}
	if l, _ := w.tb.ListLiveSessions(w.ctx, ua.ID, now0, idle); len(l) != 0 {
		t.Fatal("B lists A's sessions")
	}
	if ok, _ := w.tb.RevokeSession(w.ctx, ua.ID, sess.ID, now0); ok {
		t.Fatal("B revoked A's session")
	}
	if _, _, err := w.ta.GetLiveSession(w.ctx, hash, now0, idle); err != nil {
		t.Fatalf("A's session was affected by B: %v", err)
	}
	_ = w.tb.TouchSession(w.ctx, sess.ID, now0.Add(time.Hour))
	s2, _, _ := w.ta.GetLiveSession(w.ctx, hash, now0, idle)
	if !s2.LastActiveAt.Equal(now0) {
		t.Fatal("B touched A's session")
	}

	// The database itself refuses a session that mixes applications.
	_, h2, _ := auth.NewSessionToken()
	if _, err := w.tb.CreateSession(w.ctx, ua.ID, h2, "", "", now0, exp); err == nil {
		t.Fatal("created a session in B for A's user")
	}
	if _, err := w.ta.CreateSession(w.ctx, ub.ID, h2, "", "", now0, exp); err == nil {
		t.Fatal("created a session in A for B's user")
	}

	if ok, err := w.ta.RevokeSession(w.ctx, ua.ID, sess.ID, now0); !ok || err != nil {
		t.Fatalf("own revoke: %v %v", ok, err)
	}
	if _, _, err := w.ta.GetLiveSession(w.ctx, hash, now0, idle); !errors.Is(err, ErrNotFound) {
		t.Fatal("revoked session still live")
	}
}

func TestSessionExpiry(t *testing.T) {
	w := newWorld(t)
	u, _ := w.ta.CreateUser(w.ctx, "e@example.com", "h")
	_, hash, _ := auth.NewSessionToken()
	if _, err := w.ta.CreateSession(w.ctx, u.ID, hash, "", "", now0, now0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.ta.GetLiveSession(w.ctx, hash, now0.Add(time.Hour), now0); !errors.Is(err, ErrNotFound) {
		t.Fatal("absolute expiry not enforced")
	}
	if _, _, err := w.ta.GetLiveSession(w.ctx, hash, now0.Add(time.Minute), now0.Add(time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Fatal("idle timeout not enforced")
	}
}

// Cleanup judges each session by its own application's idle timeout.
func TestDeleteExpiredSessionsUsesPerApplicationIdleTimeout(t *testing.T) {
	w := newWorld(t)
	// A: 5-minute idle timeout. B: default 7 days.
	if _, err := w.s.UpdateApplication(w.ctx, w.dev.ID, w.a.ID, "A", ApplicationSettings{
		SessionLifetime: 24 * time.Hour, SessionIdleTimeout: 5 * time.Minute, SignupEnabled: true}); err != nil {
		t.Fatal(err)
	}
	ua, _ := w.ta.CreateUser(w.ctx, "c@example.com", "h")
	ub, _ := w.tb.CreateUser(w.ctx, "c@example.com", "h")
	_, ha, _ := auth.NewSessionToken()
	_, hb, _ := auth.NewSessionToken()
	exp := now0.Add(48 * time.Hour)
	_, _ = w.ta.CreateSession(w.ctx, ua.ID, ha, "", "", now0, exp)
	_, _ = w.tb.CreateSession(w.ctx, ub.ID, hb, "", "", now0, exp)

	if _, err := w.s.DeleteExpiredSessions(w.ctx, now0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	far := now0.Add(-24 * time.Hour)
	if _, _, err := w.ta.GetLiveSession(w.ctx, ha, now0.Add(time.Hour), far); !errors.Is(err, ErrNotFound) {
		t.Fatal("A's idle session was not deleted")
	}
	if _, _, err := w.tb.GetLiveSession(w.ctx, hb, now0.Add(time.Hour), far); err != nil {
		t.Fatalf("B's session (7-day idle timeout) was wrongly deleted: %v", err)
	}
}

func TestSigningKeysAreSeparatePerApplication(t *testing.T) {
	w := newWorld(t)
	ts, err := auth.NewTokenService(w.s, "store-test-secret-store-test-secret-1", "http://x.test", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	ta, _, err := ts.Issue(w.ctx, w.a.ID, "u", "s", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ts.Verify(w.ctx, w.a.ID, ta, now); err != nil {
		t.Fatalf("A's token against A: %v", err)
	}
	if err := ts.EnsureKey(w.ctx, w.b.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := ts.Verify(w.ctx, w.b.ID, ta, now); err == nil {
		t.Fatal("A's token verified against B")
	}
	ja, _ := ts.JWKS(w.ctx, w.a.ID, now)
	jb, _ := ts.JWKS(w.ctx, w.b.ID, now)
	if len(ja.Keys) != 1 || len(jb.Keys) != 1 || ja.Keys[0].Kid == jb.Keys[0].Kid {
		t.Fatalf("JWKS overlap: %+v %+v", ja, jb)
	}

	// Rotating A leaves B's keys alone, and rotation survives a full DB round-trip.
	if _, _, err := ts.Rotate(w.ctx, w.a.ID, now, auth.KeyActivationDelay); err != nil {
		t.Fatal(err)
	}
	ja, _ = ts.JWKS(w.ctx, w.a.ID, now)
	jb2, _ := ts.JWKS(w.ctx, w.b.ID, now)
	if len(ja.Keys) != 2 || len(jb2.Keys) != 1 {
		t.Fatalf("after rotating A: A=%d B=%d keys", len(ja.Keys), len(jb2.Keys))
	}
	if k, err := w.s.KeysFor(w.b.ID).ActiveSigningKey(w.ctx, now); err != nil || k.KID != jb.Keys[0].Kid {
		t.Fatalf("B's active key changed: %v", err)
	}
	if _, err := ts.Verify(w.ctx, w.a.ID, ta, now.Add(30*time.Second)); err != nil {
		t.Fatalf("old token after rotation: %v", err)
	}
	if k, err := w.s.KeysFor(w.a.ID).ActiveSigningKey(w.ctx, now.Add(auth.KeyActivationDelay+time.Second)); err != nil || k.KID != ja.Keys[0].Kid {
		t.Fatalf("new key not active after delay: %v", err)
	}
}

func TestApplicationLookupsAndSettings(t *testing.T) {
	w := newWorld(t)
	if got, err := w.s.ApplicationByPublishableKey(w.ctx, w.a.PublishableKey); err != nil || got.ID != w.a.ID {
		t.Fatalf("by publishable key: %v", err)
	}
	if got, err := w.s.ApplicationBySecretKeyHash(w.ctx, auth.HashSecretKey(w.skB)); err != nil || got.ID != w.b.ID {
		t.Fatalf("by secret key: %v", err)
	}
	// A publishable key is not a secret key, whichever column you try.
	if _, err := w.s.ApplicationBySecretKeyHash(w.ctx, auth.HashSecretKey(w.a.PublishableKey)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("publishable key accepted as secret: %v", err)
	}
	if _, err := w.s.ApplicationByPublishableKey(w.ctx, "pk_live_"+strings.Repeat("z", 24)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown key: %v", err)
	}
	if _, err := w.s.ApplicationByID(w.ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("malformed id: %v", err)
	}
	// Defaults.
	d := w.a.Settings
	if !d.SignupEnabled || d.SessionLifetime != 30*24*time.Hour || d.SessionIdleTimeout != 7*24*time.Hour || d.AllowedOrigins == nil {
		t.Fatalf("defaults: %+v", d)
	}
	// The secret itself is never stored.
	var n int
	_ = w.s.Pool.QueryRow(w.ctx, `SELECT count(*) FROM applications WHERE id::text = $1 AND position($2 in secret_key_hash::text) > 0`, w.a.ID, w.skA).Scan(&n)
	if n != 0 || w.a.SecretKeyLast4 != w.skA[len(w.skA)-4:] {
		t.Fatal("secret key stored or last4 wrong")
	}

	// Update, and ownership: another developer cannot touch it.
	upd, err := w.s.UpdateApplication(w.ctx, w.dev.ID, w.a.ID, "Renamed", ApplicationSettings{
		AllowedOrigins: []string{"https://a.example"}, SessionLifetime: 2 * time.Hour, SessionIdleTimeout: time.Hour, SignupEnabled: false})
	if err != nil || upd.Name != "Renamed" || upd.Settings.SignupEnabled || upd.Settings.SessionLifetime != 2*time.Hour || len(upd.Settings.AllowedOrigins) != 1 {
		t.Fatalf("update: %+v %v", upd, err)
	}
	other, _ := w.s.CreateDeveloper(w.ctx, "other-"+fmt.Sprint(time.Now().UnixNano())+"@example.com", "h")
	t.Cleanup(func() {
		_, _ = w.s.Pool.Exec(context.Background(), "DELETE FROM developers WHERE id::text = $1", other.ID)
	})
	if _, err := w.s.GetApplication(w.ctx, other.ID, w.a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another developer read the app: %v", err)
	}
	if _, err := w.s.UpdateApplication(w.ctx, other.ID, w.a.ID, "x", d); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another developer updated the app: %v", err)
	}
	if _, err := w.s.RollSecretKey(w.ctx, other.ID, w.a.ID, []byte("x"), "abcd"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another developer rolled the key: %v", err)
	}
	if l, _ := w.s.ListApplications(w.ctx, other.ID); len(l) != 0 {
		t.Fatal("another developer lists the app")
	}
	// Bounds are enforced by the database as well.
	if _, err := w.s.UpdateApplication(w.ctx, w.dev.ID, w.a.ID, "x", ApplicationSettings{SessionLifetime: time.Minute, SessionIdleTimeout: time.Minute}); err == nil {
		t.Fatal("database accepted a 1-minute session lifetime")
	}

	// Rolling the secret key kills the old one immediately.
	nk, nh, nl4, _ := auth.NewSecretKey()
	if _, err := w.s.RollSecretKey(w.ctx, w.dev.ID, w.a.ID, nh, nl4); err != nil {
		t.Fatal(err)
	}
	if _, err := w.s.ApplicationBySecretKeyHash(w.ctx, auth.HashSecretKey(w.skA)); !errors.Is(err, ErrNotFound) {
		t.Fatal("old secret key still works")
	}
	if got, err := w.s.ApplicationBySecretKeyHash(w.ctx, auth.HashSecretKey(nk)); err != nil || got.ID != w.a.ID {
		t.Fatal("new secret key does not work")
	}
}

func TestDeveloperSessions(t *testing.T) {
	w := newWorld(t)
	tok, h, _ := auth.NewDeveloperToken()
	_ = tok
	if err := w.s.CreateDeveloperSession(w.ctx, w.dev.ID, h, now0, now0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if d, err := w.s.GetLiveDeveloperSession(w.ctx, h, now0); err != nil || d.ID != w.dev.ID {
		t.Fatalf("live: %v", err)
	}
	if _, err := w.s.GetLiveDeveloperSession(w.ctx, h, now0.Add(2*time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatal("expired developer session live")
	}
	_ = w.s.RevokeDeveloperSession(w.ctx, h, now0)
	if _, err := w.s.GetLiveDeveloperSession(w.ctx, h, now0); !errors.Is(err, ErrNotFound) {
		t.Fatal("revoked developer session live")
	}
	if _, err := w.s.CreateDeveloper(w.ctx, w.dev.Email, "x"); !errors.Is(err, ErrEmailTaken) {
		t.Fatalf("dup developer: %v", err)
	}
}

// TestTenantQueriesAreScoped reads this package's own source and fails if any
// SQL touching a tenant table lacks an application_id condition. Together with
// AppStore being the only way to reach those tables, a missing filter cannot
// slip in unnoticed. The few cross-tenant statements (cleanup jobs and the mail
// queue worker) carry a "-- cross-tenant:" marker in the SQL and are counted.
func TestTenantQueriesAreScoped(t *testing.T) {
	files := []string{"users.go", "sessions.go", "signing_keys.go", "verification.go", "outbox.go"}
	rawSQL := regexp.MustCompile("(?s)`([^`]*)`")
	tenantTable := regexp.MustCompile(`(?i)\b(FROM|UPDATE|INTO|JOIN)\s+(users|sessions|signing_keys|verification_tokens|email_outbox)\b`)
	checked, crossTenant := 0, 0
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range rawSQL.FindAllStringSubmatch(string(src), -1) {
			q := m[1]
			if !tenantTable.MatchString(q) {
				continue
			}
			checked++
			if strings.Contains(q, "-- cross-tenant:") {
				crossTenant++
				continue // deliberate maintenance / queue-worker query, marked in the SQL itself
			}
			if !strings.Contains(q, "application_id = $1") && !strings.Contains(q, "(application_id,") {
				t.Errorf("%s: tenant query without application_id scope:\n%s", f, q)
			}
		}
	}
	if checked < 25 {
		t.Fatalf("only %d tenant queries found; the scan is not looking at the right code", checked)
	}
	// Cross-tenant statements are an explicit, reviewed list: adding one means updating this number.
	if crossTenant != 7 {
		t.Fatalf("%d cross-tenant statements, want 7 (sessions cleanup, token cleanup, outbox claim, sent, failed x2, outbox cleanup)", crossTenant)
	}
}
