package auth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

const (
	testSecret = "unit-test-secret-unit-test-secret-1234"
	testBase   = "http://issuer.test"
	appA       = "11111111-1111-4111-8111-111111111111"
	appB       = "22222222-2222-4222-8222-222222222222"
)

func newTestService(t *testing.T) (*TokenService, *MemoryKeyStores) {
	t.Helper()
	ks := NewMemoryKeyStores()
	ts, err := NewTokenService(ks, testSecret, testBase, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return ts, ks
}

func TestNewTokenServiceValidation(t *testing.T) {
	ks := NewMemoryKeyStores()
	if _, err := NewTokenService(ks, "too-short", testBase, 0); err == nil {
		t.Fatal("accepted a short secret")
	}
	if _, err := NewTokenService(ks, testSecret, "", 0); err == nil {
		t.Fatal("accepted an empty issuer")
	}
	ts, err := NewTokenService(ks, testSecret, testBase+"/", 0)
	if err != nil || ts.TTL() != DefaultTokenTTL {
		t.Fatalf("defaults not applied: %v %v", err, ts.TTL())
	}
	if got := ts.Issuer(appA); got != testBase+"/apps/"+appA {
		t.Fatalf("Issuer = %q", got)
	}
	if got := ts.JWKSURL(appA); got != testBase+"/apps/"+appA+"/.well-known/jwks.json" {
		t.Fatalf("JWKSURL = %q", got)
	}
	if ts.Audience(appA) != appA {
		t.Fatalf("Audience = %q", ts.Audience(appA))
	}
}

func TestIssueCreatesKeyAndVerifies(t *testing.T) {
	ctx := context.Background()
	ts, _ := newTestService(t)

	tok, exp, err := ts.Issue(ctx, appA, "user-1", "sess-1", testNow)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if want := testNow.Add(time.Minute); !exp.Equal(want) {
		t.Fatalf("exp = %v, want %v", exp, want)
	}

	claims, err := ts.Verify(ctx, appA, tok, testNow)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != "user-1" || claims.SessionID != "sess-1" || claims.ID == "" {
		t.Fatalf("claims = %+v", claims)
	}
	if claims.Issuer != ts.Issuer(appA) || !claims.Audience.Contains(appA) {
		t.Fatalf("issuer/audience = %q %v", claims.Issuer, claims.Audience)
	}
	if lifetime := claims.ExpiresAt.Time().Sub(claims.IssuedAt.Time()); lifetime != time.Minute {
		t.Fatalf("lifetime = %v, want 1m", lifetime)
	}
	if _, err := ts.Verify(ctx, appA, tok, testNow.Add(time.Minute)); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("after expiry: %v", err)
	}
}

// A token from application A must not verify against application B.
func TestTokenFromOneApplicationFailsForAnother(t *testing.T) {
	ctx := context.Background()
	ts, _ := newTestService(t)

	tokA, _, err := ts.Issue(ctx, appA, "user-1", "sess-1", testNow)
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.EnsureKey(ctx, appB, testNow); err != nil {
		t.Fatal(err)
	}

	// Through the service: B's keys do not contain A's kid.
	if _, err := ts.Verify(ctx, appB, tokA, testNow); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("A's token against B: %v, want ErrUnknownKey", err)
	}

	// Each failure on its own is enough: even with B's key set substituted for A's,
	// the issuer and the audience still reject it.
	jwksA, _ := ts.JWKS(ctx, appA, testNow)
	recsA, _ := ts.keys.KeysFor(appA).PublishedSigningKeys(ctx, testNow.Add(-KeyGrace))
	pubA, _ := parsePublicKey(recsA[0].PublicKey)
	keyA := func(string) (*ecdsa.PublicKey, error) { return pubA, nil }
	if _, err := Verify(tokA, keyA, VerifyOptions{Issuer: ts.Issuer(appB), Audience: ts.Audience(appA), Now: testNow}); !errors.Is(err, ErrWrongIssuer) {
		t.Fatalf("wrong issuer not caught: %v", err)
	}
	if _, err := Verify(tokA, keyA, VerifyOptions{Issuer: ts.Issuer(appA), Audience: ts.Audience(appB), Now: testNow}); !errors.Is(err, ErrWrongAudience) {
		t.Fatalf("wrong audience not caught: %v", err)
	}
	if len(jwksA.Keys) != 1 {
		t.Fatalf("A has %d keys", len(jwksA.Keys))
	}
}

func TestApplicationsHaveSeparateKeys(t *testing.T) {
	ctx := context.Background()
	ts, _ := newTestService(t)

	ta, _, _ := ts.Issue(ctx, appA, "u", "s", testNow)
	tb, _, _ := ts.Issue(ctx, appB, "u", "s", testNow)
	if kidOf(t, ta) == kidOf(t, tb) {
		t.Fatal("two applications signed with the same key")
	}

	ja, _ := ts.JWKS(ctx, appA, testNow)
	jb, _ := ts.JWKS(ctx, appB, testNow)
	if len(ja.Keys) != 1 || len(jb.Keys) != 1 || ja.Keys[0].Kid == jb.Keys[0].Kid {
		t.Fatalf("JWKS not separate: %+v / %+v", ja.Keys, jb.Keys)
	}

	// Rotating A leaves B alone.
	if _, _, err := ts.Rotate(ctx, appA, testNow, KeyActivationDelay); err != nil {
		t.Fatal(err)
	}
	ja, _ = ts.JWKS(ctx, appA, testNow)
	jb2, _ := ts.JWKS(ctx, appB, testNow)
	if len(ja.Keys) != 2 || len(jb2.Keys) != 1 || jb2.Keys[0].Kid != jb.Keys[0].Kid {
		t.Fatalf("rotating A changed B: A=%d B=%d", len(ja.Keys), len(jb2.Keys))
	}
}

// An encrypted private key is bound to its application: copying the stored
// blob onto another application's row must fail to decrypt.
func TestPrivateKeyBoundToApplication(t *testing.T) {
	ts, _ := newTestService(t)
	rec, err := ts.newKeyRecord(appA, testNow, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := open(ts.encKey, rec.PrivateKeyEncrypted, keyAAD(appA, rec.KID)); err != nil {
		t.Fatalf("does not decrypt for its own application: %v", err)
	}
	if _, err := open(ts.encKey, rec.PrivateKeyEncrypted, keyAAD(appB, rec.KID)); err == nil {
		t.Fatal("blob decrypted under another application")
	}
	if _, err := open(ts.encKey, rec.PrivateKeyEncrypted, keyAAD(appA, "other-kid")); err == nil {
		t.Fatal("blob decrypted under another kid")
	}
	var anyJSON any
	if err := json.Unmarshal(rec.PrivateKeyEncrypted, &anyJSON); err == nil {
		t.Fatal("sealed key looks like plain JSON")
	}

	// Moving the row between applications at the storage layer breaks signing, loudly.
	ctx := context.Background()
	ks := NewMemoryKeyStores()
	svc, _ := NewTokenService(ks, testSecret, testBase, time.Minute)
	if _, _, err := svc.Issue(ctx, appA, "u", "s", testNow); err != nil {
		t.Fatal(err)
	}
	stolen, _ := ks.KeysFor(appA).ActiveSigningKey(ctx, testNow)
	if err := ks.KeysFor(appB).CreateSigningKey(ctx, stolen); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Issue(ctx, appB, "u", "s", testNow); err == nil {
		t.Fatal("signed with a private key copied from another application")
	}
}

func TestTokensHaveUniqueIDs(t *testing.T) {
	ctx := context.Background()
	ts, _ := newTestService(t)
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		tok, _, err := ts.Issue(ctx, appA, "u", "s", testNow)
		if err != nil {
			t.Fatal(err)
		}
		c, err := ts.Verify(ctx, appA, tok, testNow)
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
	if err := ts.EnsureKey(ctx, appA, testNow); err != nil {
		t.Fatal(err)
	}
	jwks, err := ts.JWKS(ctx, appA, testNow)
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

func TestJWKSForApplicationWithoutKeysIsEmpty(t *testing.T) {
	ts, _ := newTestService(t)
	jwks, err := ts.JWKS(context.Background(), appA, testNow)
	if err != nil || len(jwks.Keys) != 0 {
		t.Fatalf("JWKS = %+v, %v", jwks, err)
	}
}

func TestEnsureKeyIsIdempotent(t *testing.T) {
	ctx := context.Background()
	ts, ks := newTestService(t)
	for i := 0; i < 3; i++ {
		if err := ts.EnsureKey(ctx, appA, testNow); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(ks.byApp[appA].keys); n != 1 {
		t.Fatalf("keys = %d, want 1", n)
	}
}

func TestKeyRotation(t *testing.T) {
	ctx := context.Background()
	ts, _ := newTestService(t)

	oldTok, _, err := ts.Issue(ctx, appA, "user-1", "sess-1", testNow)
	if err != nil {
		t.Fatal(err)
	}
	oldKid := kidOf(t, oldTok)

	rotatedAt := testNow.Add(30 * time.Second)
	newKid, activeFrom, err := ts.Rotate(ctx, appA, rotatedAt, KeyActivationDelay)
	if err != nil {
		t.Fatal(err)
	}
	if newKid == oldKid || !activeFrom.Equal(rotatedAt.Add(KeyActivationDelay)) {
		t.Fatalf("rotation = %s %v", newKid, activeFrom)
	}

	// The new key is published at once, ahead of its first token.
	jwks, _ := ts.JWKS(ctx, appA, rotatedAt)
	if len(jwks.Keys) != 2 || jwks.Keys[0].Kid != newKid || jwks.Keys[1].Kid != oldKid {
		t.Fatalf("JWKS right after rotation = %+v", jwks.Keys)
	}

	// ...but during the delay the OLD key still signs, so no token needs a key
	// that verifiers have not had time to cache.
	during, _, err := ts.Issue(ctx, appA, "user-1", "sess-1", rotatedAt.Add(KeyActivationDelay-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if kidOf(t, during) != oldKid {
		t.Fatal("new key signed before its activation time")
	}

	// From the activation time the NEW key signs.
	after := activeFrom
	newTok, _, err := ts.Issue(ctx, appA, "user-1", "sess-1", after)
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
		if _, err := ts.Verify(ctx, appA, c.tok, c.at); err != nil {
			t.Errorf("token %s: %v", c.name, err)
		}
	}
	if _, err := ts.Verify(ctx, appA, during, activeFrom.Add(30*time.Second)); err != nil {
		t.Errorf("old-key token just after the switch: %v", err)
	}

	// The old key leaves the JWKS only KeyGrace after it stopped signing.
	jwks, _ = ts.JWKS(ctx, appA, after.Add(KeyGrace-time.Second))
	if len(jwks.Keys) != 2 {
		t.Fatalf("old key dropped too early: %+v", jwks.Keys)
	}
	jwks, _ = ts.JWKS(ctx, appA, after.Add(KeyGrace+time.Second))
	if len(jwks.Keys) != 1 || jwks.Keys[0].Kid != newKid {
		t.Fatalf("JWKS after grace = %+v", jwks.Keys)
	}
}

func TestImmediateRotationForDevelopment(t *testing.T) {
	ctx := context.Background()
	ts, _ := newTestService(t)
	if err := ts.EnsureKey(ctx, appA, testNow); err != nil {
		t.Fatal(err)
	}
	newKid, _, err := ts.Rotate(ctx, appA, testNow.Add(time.Second), 0)
	if err != nil {
		t.Fatal(err)
	}
	tok, _, err := ts.Issue(ctx, appA, "u", "s", testNow.Add(time.Second))
	if err != nil || kidOf(t, tok) != newKid {
		t.Fatalf("zero-delay rotation did not switch at once: %v", err)
	}
	if _, _, err := ts.Rotate(ctx, appA, testNow, -time.Second); err == nil {
		t.Fatal("accepted a negative delay")
	}
}

// A second rotation while the first is still pending must leave exactly one
// signing key at every moment.
func TestRotateWhileRotationPending(t *testing.T) {
	ctx := context.Background()
	ts, _ := newTestService(t)
	first, _, _ := ts.Issue(ctx, appA, "u", "s", testNow)

	k2, a2, _ := ts.Rotate(ctx, appA, testNow.Add(time.Minute), 10*time.Minute)
	k3, a3, _ := ts.Rotate(ctx, appA, testNow.Add(2*time.Minute), 10*time.Minute)

	for _, step := range []struct {
		at   time.Time
		want string
	}{
		{testNow.Add(5 * time.Minute), kidOf(t, first)}, // both rotations still pending
		{a2.Add(time.Second), k2},                       // first rotation took effect
		{a3.Add(time.Second), k3},                       // second took effect
	} {
		tok, _, err := ts.Issue(ctx, appA, "u", "s", step.at)
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
	ks := NewMemoryKeyStores()
	a, _ := NewTokenService(ks, testSecret, testBase, time.Minute)
	if err := a.EnsureKey(ctx, appA, testNow); err != nil {
		t.Fatal(err)
	}
	b, _ := NewTokenService(ks, "a-completely-different-secret-value-999", testBase, time.Minute)
	if _, _, err := b.Issue(ctx, appA, "u", "s", testNow); err == nil {
		t.Fatal("decrypted a signing key with the wrong secret")
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
	if key.X.Cmp(new(big.Int).SetBytes(x)) != 0 || key.Y.Cmp(new(big.Int).SetBytes(y)) != 0 {
		t.Fatal("JWK coordinates do not match the key")
	}
}

func kidOf(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	raw, err := strictB64.DecodeString(parts[0])
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
