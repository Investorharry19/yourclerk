package auth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
	"time"
)

const testSecret = "unit-test-secret-unit-test-secret-1234"

func newTestService(t *testing.T) (*TokenService, *MemoryKeyStore) {
	t.Helper()
	ks := NewMemoryKeyStore()
	ts, err := NewTokenService(ks, testSecret, testIssuer, testAudience, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return ts, ks
}

func TestNewTokenServiceValidation(t *testing.T) {
	ks := NewMemoryKeyStore()
	if _, err := NewTokenService(ks, "too-short", testIssuer, "", 0); err == nil {
		t.Fatal("accepted a short secret")
	}
	if _, err := NewTokenService(ks, testSecret, "", "", 0); err == nil {
		t.Fatal("accepted an empty issuer")
	}
	ts, err := NewTokenService(ks, testSecret, testIssuer, "", 0)
	if err != nil || ts.Audience() != DefaultAudience || ts.TTL() != DefaultTokenTTL {
		t.Fatalf("defaults not applied: %v %v %v", err, ts.Audience(), ts.TTL())
	}
}

func TestIssueCreatesKeyAndVerifies(t *testing.T) {
	ctx := context.Background()
	ts, _ := newTestService(t)

	tok, exp, err := ts.Issue(ctx, "user-1", "sess-1", testNow)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if want := testNow.Add(time.Minute); !exp.Equal(want) {
		t.Fatalf("exp = %v, want %v", exp, want)
	}

	claims, err := ts.Verify(ctx, tok, testNow)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != "user-1" || claims.SessionID != "sess-1" || claims.ID == "" {
		t.Fatalf("claims = %+v", claims)
	}
	if lifetime := claims.ExpiresAt.Time().Sub(claims.IssuedAt.Time()); lifetime != time.Minute {
		t.Fatalf("lifetime = %v, want 1m", lifetime)
	}

	// Expired a minute later.
	if _, err := ts.Verify(ctx, tok, testNow.Add(time.Minute)); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("after expiry: %v", err)
	}
}

func TestTokensHaveUniqueIDs(t *testing.T) {
	ctx := context.Background()
	ts, _ := newTestService(t)
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		tok, _, err := ts.Issue(ctx, "u", "s", testNow)
		if err != nil {
			t.Fatal(err)
		}
		c, err := ts.Verify(ctx, tok, testNow)
		if err != nil {
			t.Fatal(err)
		}
		if seen[c.ID] {
			t.Fatal("duplicate jti")
		}
		seen[c.ID] = true
	}
}

func TestJWKSPublishesOnlyPublicKeys(t *testing.T) {
	ctx := context.Background()
	ts, _ := newTestService(t)
	if err := ts.EnsureKey(ctx, testNow); err != nil {
		t.Fatal(err)
	}
	jwks, err := ts.JWKS(ctx, testNow)
	if err != nil || len(jwks.Keys) != 1 {
		t.Fatalf("JWKS = %+v, %v", jwks, err)
	}
	k := jwks.Keys[0]
	if k.Kty != "EC" || k.Crv != "P-256" || k.Alg != "ES256" || k.Use != "sig" || k.Kid == "" || k.X == "" || k.Y == "" {
		t.Fatalf("bad JWK: %+v", k)
	}
	raw, _ := json.Marshal(jwks)
	if bytes.Contains(raw, []byte(`"d"`)) {
		t.Fatalf("JWKS leaks a private component: %s", raw)
	}
}

func TestEnsureKeyIsIdempotent(t *testing.T) {
	ctx := context.Background()
	ts, ks := newTestService(t)
	for i := 0; i < 3; i++ {
		if err := ts.EnsureKey(ctx, testNow); err != nil {
			t.Fatal(err)
		}
	}
	if len(ks.keys) != 1 {
		t.Fatalf("keys = %d, want 1", len(ks.keys))
	}
}

func TestKeyRotation(t *testing.T) {
	ctx := context.Background()
	ts, _ := newTestService(t)

	oldTok, _, err := ts.Issue(ctx, "user-1", "sess-1", testNow)
	if err != nil {
		t.Fatal(err)
	}
	oldKid := kidOf(t, oldTok)

	rotatedAt := testNow.Add(30 * time.Second)
	newKid, activeFrom, err := ts.Rotate(ctx, rotatedAt, KeyActivationDelay)
	if err != nil {
		t.Fatal(err)
	}
	if newKid == oldKid || !activeFrom.Equal(rotatedAt.Add(KeyActivationDelay)) {
		t.Fatalf("rotation = %s %v", newKid, activeFrom)
	}

	// The new key is published at once, ahead of its first token.
	jwks, _ := ts.JWKS(ctx, rotatedAt)
	if len(jwks.Keys) != 2 || jwks.Keys[0].Kid != newKid || jwks.Keys[1].Kid != oldKid {
		t.Fatalf("JWKS right after rotation = %+v", jwks.Keys)
	}

	// ...but during the delay the OLD key still signs, so no token needs a key
	// that verifiers have not had time to cache.
	during, _, err := ts.Issue(ctx, "user-1", "sess-1", rotatedAt.Add(KeyActivationDelay-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if kidOf(t, during) != oldKid {
		t.Fatal("new key signed before its activation time")
	}

	// From the activation time the NEW key signs.
	after := activeFrom
	newTok, _, err := ts.Issue(ctx, "user-1", "sess-1", after)
	if err != nil {
		t.Fatal(err)
	}
	if kidOf(t, newTok) != newKid {
		t.Fatal("new key did not take over at its activation time")
	}

	// Each token verifies at a time when it is still within its lifetime, using
	// whatever keys the JWKS held then: the old key's tokens keep working across the switch.
	for _, c := range []struct {
		name string
		tok  string
		at   time.Time
	}{
		{"signed before rotation", oldTok, rotatedAt},
		{"signed during the delay", during, rotatedAt.Add(KeyActivationDelay - time.Second)},
		{"signed by the new key", newTok, after},
	} {
		if _, err := ts.Verify(ctx, c.tok, c.at); err != nil {
			t.Errorf("token %s: %v", c.name, err)
		}
	}
	// A token signed by the old key just before the switch is still verifiable right after it.
	if _, err := ts.Verify(ctx, during, activeFrom.Add(30*time.Second)); err != nil {
		t.Errorf("old-key token just after the switch: %v", err)
	}

	// The old key leaves the JWKS only KeyGrace after it stopped signing.
	jwks, _ = ts.JWKS(ctx, after.Add(KeyGrace-time.Second))
	if len(jwks.Keys) != 2 {
		t.Fatalf("old key dropped too early: %+v", jwks.Keys)
	}
	jwks, _ = ts.JWKS(ctx, after.Add(KeyGrace+time.Second))
	if len(jwks.Keys) != 1 || jwks.Keys[0].Kid != newKid {
		t.Fatalf("JWKS after grace = %+v", jwks.Keys)
	}
}

func TestImmediateRotationForDevelopment(t *testing.T) {
	ctx := context.Background()
	ts, _ := newTestService(t)
	if err := ts.EnsureKey(ctx, testNow); err != nil {
		t.Fatal(err)
	}
	newKid, _, err := ts.Rotate(ctx, testNow.Add(time.Second), 0)
	if err != nil {
		t.Fatal(err)
	}
	tok, _, err := ts.Issue(ctx, "u", "s", testNow.Add(time.Second))
	if err != nil || kidOf(t, tok) != newKid {
		t.Fatalf("zero-delay rotation did not switch at once: %v", err)
	}
	if _, _, err := ts.Rotate(ctx, testNow, -time.Second); err == nil {
		t.Fatal("accepted a negative delay")
	}
}

// A second rotation while the first is still pending must leave exactly one
// signing key at every moment.
func TestRotateWhileRotationPending(t *testing.T) {
	ctx := context.Background()
	ts, _ := newTestService(t)
	first, _, _ := ts.Issue(ctx, "u", "s", testNow)

	k2, a2, _ := ts.Rotate(ctx, testNow.Add(time.Minute), 10*time.Minute)
	k3, a3, _ := ts.Rotate(ctx, testNow.Add(2*time.Minute), 10*time.Minute)

	for _, step := range []struct {
		at   time.Time
		want string
	}{
		{testNow.Add(5 * time.Minute), kidOf(t, first)}, // both rotations still pending
		{a2.Add(time.Second), k2},                       // first rotation took effect
		{a3.Add(time.Second), k3},                       // second took effect
	} {
		tok, _, err := ts.Issue(ctx, "u", "s", step.at)
		if err != nil {
			t.Fatal(err)
		}
		if got := kidOf(t, tok); got != step.want {
			t.Fatalf("at %v signed with %s, want %s", step.at, got, step.want)
		}
	}
}

// The activation delay must outlast every JWKS cache, or the point of
// publishing early is lost.
func TestActivationDelayOutlastsCaches(t *testing.T) {
	if KeyActivationDelay < 2*JWKSCacheMaxAge {
		t.Fatalf("KeyActivationDelay %v is shorter than twice JWKSCacheMaxAge %v", KeyActivationDelay, JWKSCacheMaxAge)
	}
	if KeyGrace < KeyActivationDelay {
		t.Fatalf("KeyGrace %v shorter than KeyActivationDelay %v", KeyGrace, KeyActivationDelay)
	}
}

func TestWrongSecretCannotUseStoredKeys(t *testing.T) {
	ctx := context.Background()
	ks := NewMemoryKeyStore()
	a, _ := NewTokenService(ks, testSecret, testIssuer, testAudience, time.Minute)
	if err := a.EnsureKey(ctx, testNow); err != nil {
		t.Fatal(err)
	}
	b, _ := NewTokenService(ks, "a-completely-different-secret-value-999", testIssuer, testAudience, time.Minute)
	if _, _, err := b.Issue(ctx, "u", "s", testNow); err == nil {
		t.Fatal("decrypted a signing key with the wrong secret")
	}
}

func TestPrivateKeyNotStoredInPlain(t *testing.T) {
	ts, _ := newTestService(t)
	rec, err := ts.newKeyRecord(testNow, testNow)
	if err != nil {
		t.Fatal(err)
	}
	// A PKCS#8 DER key starts with an ASN.1 SEQUENCE (0x30); the sealed blob starts with a random nonce
	// and must not parse as a key.
	if _, err := ts.keys.ActiveSigningKey(context.Background(), testNow); !errors.Is(err, ErrNoSigningKey) {
		t.Fatalf("setup: %v", err)
	}
	var priv any
	if err := json.Unmarshal(rec.PrivateKeyEncrypted, &priv); err == nil {
		t.Fatal("sealed key looks like plain JSON")
	}
	// Moving the blob under another kid must fail authentication.
	if _, err := open(ts.encKey, rec.PrivateKeyEncrypted, []byte("different-kid")); err == nil {
		t.Fatal("blob decrypted under a different kid")
	}
	if _, err := open(ts.encKey, rec.PrivateKeyEncrypted, []byte(rec.KID)); err != nil {
		t.Fatalf("blob does not decrypt under its own kid: %v", err)
	}
}

func TestJWKRoundTripMatchesPublicKey(t *testing.T) {
	key := mustKey(t)
	jwk := JWKFromPublicKey("k", &key.PublicKey)
	x, err := strictB64.DecodeString(jwk.X)
	if err != nil || len(x) != 32 {
		t.Fatalf("x: %v len=%d", err, len(x))
	}
	y, err := strictB64.DecodeString(jwk.Y)
	if err != nil || len(y) != 32 {
		t.Fatalf("y: %v len=%d", err, len(y))
	}
	var _ *ecdsa.PublicKey = &key.PublicKey
	if key.X.Cmp(newBig(x)) != 0 || key.Y.Cmp(newBig(y)) != 0 {
		t.Fatal("JWK coordinates do not match the key")
	}
}

func kidOf(t *testing.T, token string) string {
	t.Helper()
	parts := bytes.Split([]byte(token), []byte("."))
	raw, err := strictB64.DecodeString(string(parts[0]))
	if err != nil {
		t.Fatal(err)
	}
	var h struct {
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	return h.Kid
}

func newBig(b []byte) *big.Int { return new(big.Int).SetBytes(b) }
