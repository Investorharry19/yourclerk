package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/Investorharry19/yourclerk/internal/auth"
)

// Runs against a real Postgres with migrations applied. Skipped without TEST_DATABASE_URL.
// It wipes the signing_keys table first, so only point it at a throwaway database.
func TestSigningKeysAndRotation(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s, err := New(ctx, url)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	if _, err := s.Pool.Exec(ctx, "DELETE FROM signing_keys"); err != nil {
		t.Fatalf("clean signing_keys (did you run `make migrate-up`?): %v", err)
	}
	t.Cleanup(func() { _, _ = s.Pool.Exec(context.Background(), "DELETE FROM signing_keys") })

	if _, err := s.ActiveSigningKey(ctx, time.Now()); !errors.Is(err, auth.ErrNoSigningKey) {
		t.Fatalf("empty table: got %v, want ErrNoSigningKey", err)
	}

	// Drive the real service on top of the real store.
	secret := fmt.Sprintf("integration-test-secret-%d-padding-padding", time.Now().UnixNano())
	ts, err := auth.NewTokenService(s, secret, "http://issuer.test", "yourclerk", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)

	oldTok, _, err := ts.Issue(ctx, "user-1", "sess-1", now) // creates the first key on demand
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	first, err := s.ActiveSigningKey(ctx, now)
	if err != nil || first.RetiredAt != nil {
		t.Fatalf("active key = %+v, %v", first, err)
	}
	if len(first.PrivateKeyEncrypted) == 0 || string(first.PrivateKeyEncrypted) == string(first.PublicKey) {
		t.Fatal("private key not stored encrypted")
	}

	// A fresh service instance (same secret) can read the key back: keys survive restarts.
	ts2, _ := auth.NewTokenService(s, secret, "http://issuer.test", "yourclerk", time.Minute)
	if _, err := ts2.Verify(ctx, oldTok, now); err != nil {
		t.Fatalf("second instance cannot verify: %v", err)
	}
	// And a different secret cannot use them.
	bad, _ := auth.NewTokenService(s, "a-different-secret-a-different-secret-1", "http://issuer.test", "yourclerk", time.Minute)
	if _, _, err := bad.Issue(ctx, "u", "s", now); err == nil {
		t.Fatal("wrong SECRET_KEY decrypted the stored key")
	}

	rotatedAt := now.Add(30 * time.Second)
	newKid, activeFrom, err := ts.Rotate(ctx, rotatedAt, auth.KeyActivationDelay)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	// Published immediately, but the old key still signs until activeFrom.
	published, err := s.PublishedSigningKeys(ctx, rotatedAt.Add(-auth.KeyGrace))
	if err != nil || len(published) != 2 || published[0].KID != newKid || published[1].KID != first.KID {
		t.Fatalf("published = %+v, %v", published, err)
	}
	if published[1].RetiredAt == nil || !published[1].RetiredAt.Equal(activeFrom) {
		t.Fatalf("old key retirement = %v, want %v", published[1].RetiredAt, activeFrom)
	}
	during, err := s.ActiveSigningKey(ctx, activeFrom.Add(-time.Second))
	if err != nil || during.KID != first.KID {
		t.Fatalf("signing key during the delay = %+v, %v; want the old key", during, err)
	}
	after, err := s.ActiveSigningKey(ctx, activeFrom)
	if err != nil || after.KID != newKid {
		t.Fatalf("signing key at activation = %+v, %v; want the new key", after, err)
	}

	// Tokens signed before the switch verify during and after it.
	if _, err := ts.Verify(ctx, oldTok, rotatedAt); err != nil {
		t.Fatalf("old token after rotation: %v", err)
	}
	newTok, _, err := ts.Issue(ctx, "user-1", "sess-1", activeFrom)
	if err != nil {
		t.Fatalf("Issue after activation: %v", err)
	}
	if _, err := ts.Verify(ctx, newTok, activeFrom); err != nil {
		t.Fatalf("new token: %v", err)
	}

	// The old key drops out of the JWKS only after the grace period.
	published, _ = s.PublishedSigningKeys(ctx, activeFrom.Add(auth.KeyGrace+time.Hour).Add(-auth.KeyGrace))
	if len(published) != 1 || published[0].KID != newKid {
		t.Fatalf("published after grace = %+v", published)
	}
}
