package yourclerk

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestVerifyValidToken(t *testing.T) {
	clk := newClock()
	iss := newFakeIssuer(t, clk)
	key := iss.addKey("k1")
	c := iss.client(clk)

	claims, err := c.VerifyToken(context.Background(), iss.token(key))
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if claims.UserID() != testSubject || claims.SessionID != "sess-1" || claims.ID != "jti-1" || claims.Issuer != iss.URL() {
		t.Fatalf("claims = %+v", claims)
	}
	if want := clk.Now().Add(time.Minute); !claims.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt = %v, want %v", claims.ExpiresAt, want)
	}
}

func TestVerifyAcceptsAudienceArray(t *testing.T) {
	clk := newClock()
	iss := newFakeIssuer(t, clk)
	key := iss.addKey("k1")
	c := iss.client(clk)

	tok := iss.token(key, withClaim("aud", []string{"other", testAudience}))
	if _, err := c.VerifyToken(context.Background(), tok); err != nil {
		t.Fatalf("array aud: %v", err)
	}
}

// TestRejectsBadTokens covers the five failures the plan names (tampered
// payload, wrong key, expired, wrong issuer, alg none) plus nearby tricks.
func TestRejectsBadTokens(t *testing.T) {
	clk := newClock()
	iss := newFakeIssuer(t, clk)
	key := iss.addKey("k1")
	attacker := iss.newKey("k1") // same kid, different private key
	c := iss.client(clk)

	good := iss.token(key)
	parts := strings.Split(good, ".")

	tamperedClaims := iss.claims(withClaim("sub", "admin"))
	tampered := parts[0] + "." + rawB64.EncodeToString(mustJSON(tamperedClaims)) + "." + parts[2]

	craft := func(header map[string]any, sig string) string {
		return rawB64.EncodeToString(mustJSON(header)) + "." + rawB64.EncodeToString(mustJSON(iss.claims())) + "." + sig
	}

	hmacInput := rawB64.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT","kid":"k1"}`)) + "." + rawB64.EncodeToString(mustJSON(iss.claims()))
	mac := hmac.New(sha256.New, []byte("guessed-secret"))
	mac.Write([]byte(hmacInput))
	hs256 := hmacInput + "." + rawB64.EncodeToString(mac.Sum(nil))

	tests := []struct {
		name  string
		token string
		want  error
	}{
		{"tampered payload", tampered, ErrInvalidToken},
		{"wrong key", iss.token(attacker), ErrInvalidToken},
		{"expired", iss.token(key, withClaim("exp", clk.Now().Add(-time.Minute).Unix())), ErrTokenExpired},
		{"not yet valid", iss.token(key, withClaim("nbf", clk.Now().Add(time.Hour).Unix())), ErrTokenNotYetValid},
		{"wrong issuer", iss.token(key, withClaim("iss", "https://evil.example")), ErrWrongIssuer},
		{"wrong audience", iss.token(key, withClaim("aud", "someone-else")), ErrWrongAudience},
		{"missing audience", iss.token(key, without("aud")), ErrWrongAudience},
		{"missing exp", iss.token(key, without("exp")), ErrInvalidToken},
		{"missing sub", iss.token(key, without("sub")), ErrInvalidToken},
		{"alg none, empty signature", craft(map[string]any{"alg": "none", "typ": "JWT", "kid": "k1"}, ""), ErrInvalidToken},
		{"alg none, signature kept", craft(map[string]any{"alg": "none", "typ": "JWT", "kid": "k1"}, parts[2]), ErrInvalidToken},
		{"alg None", craft(map[string]any{"alg": "None", "kid": "k1"}, ""), ErrInvalidToken},
		{"alg HS256 confusion", hs256, ErrInvalidToken},
		{"alg RS256 claimed", craft(map[string]any{"alg": "RS256", "kid": "k1"}, parts[2]), ErrInvalidToken},
		{"missing kid", craft(map[string]any{"alg": "ES256"}, parts[2]), ErrInvalidToken},
		{"crit header", craft(map[string]any{"alg": "ES256", "kid": "k1", "crit": []string{"exp"}}, parts[2]), ErrInvalidToken},
		{"empty", "", ErrInvalidToken},
		{"two parts", parts[0] + "." + parts[1], ErrInvalidToken},
		{"four parts", good + ".x", ErrInvalidToken},
		{"padded base64", parts[0] + "=." + parts[1] + "." + parts[2], ErrInvalidToken},
		{"garbage", "a.b.c", ErrInvalidToken},
		{"short signature", parts[0] + "." + parts[1] + "." + rawB64.EncodeToString([]byte("short")), ErrInvalidToken},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := c.VerifyToken(context.Background(), tc.token)
			if err == nil {
				t.Fatalf("accepted a bad token: %+v", claims)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestLeeway(t *testing.T) {
	clk := newClock()
	iss := newFakeIssuer(t, clk)
	key := iss.addKey("k1")
	c := iss.client(clk) // default leeway 5s

	justExpired := iss.token(key, withClaim("exp", clk.Now().Add(-2*time.Second).Unix()))
	if _, err := c.VerifyToken(context.Background(), justExpired); err != nil {
		t.Fatalf("within leeway: %v", err)
	}
	longExpired := iss.token(key, withClaim("exp", clk.Now().Add(-10*time.Second).Unix()))
	if _, err := c.VerifyToken(context.Background(), longExpired); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("beyond leeway: %v", err)
	}
}

func TestNoNetworkOnHotPath(t *testing.T) {
	clk := newClock()
	iss := newFakeIssuer(t, clk)
	key := iss.addKey("k1")
	c := iss.client(clk)

	for i := 0; i < 500; i++ {
		if _, err := c.VerifyToken(context.Background(), iss.token(key)); err != nil {
			t.Fatalf("verification %d: %v", i, err)
		}
	}
	if got := iss.fetches.Load(); got != 1 {
		t.Fatalf("JWKS fetched %d times for 500 verifications, want 1", got)
	}
}

func TestConcurrentColdStartFetchesOnce(t *testing.T) {
	clk := newClock()
	iss := newFakeIssuer(t, clk)
	key := iss.addKey("k1")
	c := iss.client(clk)
	tok := iss.token(key)

	var wg sync.WaitGroup
	errs := make(chan error, 50)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.VerifyToken(context.Background(), tok); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent verify: %v", err)
	}
	if got := iss.fetches.Load(); got != 1 {
		t.Fatalf("JWKS fetched %d times by 50 concurrent first requests, want 1", got)
	}
}

// TestKeyRotation: after the issuer adds a new key, tokens signed by the old key
// keep verifying with no refetch, and tokens signed by the new key verify after one refetch.
func TestKeyRotation(t *testing.T) {
	clk := newClock()
	iss := newFakeIssuer(t, clk)
	oldKey := iss.addKey("old")
	c := iss.client(clk)
	ctx := context.Background()

	oldTok := iss.token(oldKey)
	if _, err := c.VerifyToken(ctx, oldTok); err != nil {
		t.Fatal(err)
	}

	newKey := iss.addKey("new") // rotation: both keys now published
	clk.Advance(30 * time.Second)

	// Old tokens still verify straight from cache.
	before := iss.fetches.Load()
	if _, err := c.VerifyToken(ctx, iss.token(oldKey)); err != nil {
		t.Fatalf("old key after rotation: %v", err)
	}
	if iss.fetches.Load() != before {
		t.Fatal("verifying an old-key token caused a fetch")
	}

	// A new-key token triggers exactly one refetch and then verifies.
	if _, err := c.VerifyToken(ctx, iss.token(newKey)); err != nil {
		t.Fatalf("new key after rotation: %v", err)
	}
	if got := iss.fetches.Load() - before; got != 1 {
		t.Fatalf("rotation caused %d fetches, want 1", got)
	}
	if _, err := c.VerifyToken(ctx, iss.token(oldKey)); err != nil {
		t.Fatalf("old key after refetch: %v", err)
	}
	if _, err := c.VerifyToken(ctx, iss.token(newKey)); err != nil {
		t.Fatalf("new key second use: %v", err)
	}
}

func TestUnknownKidRefetchIsRateLimited(t *testing.T) {
	clk := newClock()
	iss := newFakeIssuer(t, clk)
	key := iss.addKey("k1")
	c := iss.client(clk)
	ctx := context.Background()

	if _, err := c.VerifyToken(ctx, iss.token(key)); err != nil {
		t.Fatal(err)
	}
	start := iss.fetches.Load()

	stranger := iss.newKey("never-published")
	for i := 0; i < 100; i++ {
		clk.Advance(50 * time.Millisecond)
		_, err := c.VerifyToken(ctx, iss.token(stranger))
		if !errors.Is(err, ErrUnknownKey) {
			t.Fatalf("attempt %d: %v, want ErrUnknownKey", i, err)
		}
	}
	// 100 attempts over 5 seconds, with a 10s minimum gap, must not hit the issuer at all.
	if got := iss.fetches.Load() - start; got != 0 {
		t.Fatalf("unknown kid flood caused %d fetches, want 0", got)
	}

	// Once the gap has passed one more attempt is allowed through.
	clk.Advance(11 * time.Second)
	if _, err := c.VerifyToken(ctx, iss.token(stranger)); !errors.Is(err, ErrUnknownKey) {
		t.Fatal("stranger accepted")
	}
	if got := iss.fetches.Load() - start; got != 1 {
		t.Fatalf("after the gap: %d fetches, want 1", got)
	}
}

func TestCacheRefreshesAfterTTLAndSurvivesOutage(t *testing.T) {
	clk := newClock()
	iss := newFakeIssuer(t, clk)
	key := iss.addKey("k1")
	c := iss.client(clk, func(cfg *Config) { cfg.CacheTTL = time.Minute })
	ctx := context.Background()

	if _, err := c.VerifyToken(ctx, iss.token(key)); err != nil {
		t.Fatal(err)
	}

	// Past the TTL the next verification refreshes the keys.
	clk.Advance(2 * time.Minute)
	before := iss.fetches.Load()
	if _, err := c.VerifyToken(ctx, iss.token(key)); err != nil {
		t.Fatal(err)
	}
	if iss.fetches.Load()-before != 1 {
		t.Fatal("stale cache was not refreshed")
	}

	// If the issuer is down when the cache goes stale, the old keys keep working.
	iss.setDown(true)
	clk.Advance(2 * time.Minute)
	for i := 0; i < 5; i++ {
		clk.Advance(11 * time.Second)
		if _, err := c.VerifyToken(ctx, iss.token(key)); err != nil {
			t.Fatalf("during outage: %v", err)
		}
	}

	// And it recovers when the issuer returns.
	iss.setDown(false)
	clk.Advance(11 * time.Second)
	if _, err := c.VerifyToken(ctx, iss.token(key)); err != nil {
		t.Fatalf("after recovery: %v", err)
	}
}

func TestColdStartWithIssuerDown(t *testing.T) {
	clk := newClock()
	iss := newFakeIssuer(t, clk)
	key := iss.addKey("k1")
	iss.setDown(true)
	c := iss.client(clk)

	if _, err := c.VerifyToken(context.Background(), iss.token(key)); !errors.Is(err, ErrJWKSUnavailable) {
		t.Fatalf("got %v, want ErrJWKSUnavailable", err)
	}

	// Within the gap we do not hammer the issuer, and the error stays the same.
	before := iss.fetches.Load()
	if _, err := c.VerifyToken(context.Background(), iss.token(key)); !errors.Is(err, ErrJWKSUnavailable) {
		t.Fatalf("second try: %v", err)
	}
	if iss.fetches.Load() != before {
		t.Fatal("retried the issuer inside the minimum gap")
	}

	iss.setDown(false)
	clk.Advance(11 * time.Second)
	if _, err := c.VerifyToken(context.Background(), iss.token(key)); err != nil {
		t.Fatalf("after the issuer came back: %v", err)
	}
}

func TestJWKSParsingSkipsUnusableKeys(t *testing.T) {
	clk := newClock()
	iss := newFakeIssuer(t, clk)
	good := iss.addKey("good")

	valid := jwkFor(good)
	offCurve := jwk{Kty: "EC", Crv: "P-256", Kid: "off-curve", Alg: "ES256", Use: "sig", X: valid.X, Y: rawB64.EncodeToString(make([]byte, 32))}
	iss.mu.Lock()
	iss.extra = []jwk{
		{Kty: "RSA", Kid: "rsa", Alg: "RS256", Use: "sig", X: "AQAB"},
		offCurve,
		{Kty: "EC", Crv: "P-384", Kid: "p384", Alg: "ES384", Use: "sig", X: valid.X, Y: valid.Y},
		{Kty: "EC", Crv: "P-256", Kid: "enc-only", Alg: "ES256", Use: "enc", X: valid.X, Y: valid.Y},
		{Kty: "EC", Crv: "P-256", Kid: "", Alg: "ES256", Use: "sig", X: valid.X, Y: valid.Y},
		{Kty: "EC", Crv: "P-256", Kid: "short-x", Alg: "ES256", Use: "sig", X: "AAAA", Y: valid.Y},
	}
	iss.mu.Unlock()
	c := iss.client(clk)

	if _, err := c.VerifyToken(context.Background(), iss.token(good)); err != nil {
		t.Fatalf("good key rejected: %v", err)
	}
	for _, kid := range []string{"rsa", "off-curve", "p384", "enc-only", "short-x"} {
		clk.Advance(11 * time.Second)
		if _, err := c.VerifyToken(context.Background(), iss.token(testKey{kid: kid, priv: good.priv})); !errors.Is(err, ErrUnknownKey) {
			t.Errorf("kid %q: got %v, want ErrUnknownKey", kid, err)
		}
	}
}

func TestEmptyJWKSDoesNotWipeCache(t *testing.T) {
	clk := newClock()
	iss := newFakeIssuer(t, clk)
	key := iss.addKey("k1")
	c := iss.client(clk, func(cfg *Config) { cfg.CacheTTL = time.Minute })
	ctx := context.Background()

	if _, err := c.VerifyToken(ctx, iss.token(key)); err != nil {
		t.Fatal(err)
	}
	// The issuer starts returning an empty key set (a bug or an attack).
	iss.mu.Lock()
	iss.keys = nil
	iss.mu.Unlock()
	clk.Advance(2 * time.Minute)
	if _, err := c.VerifyToken(ctx, iss.token(key)); err != nil {
		t.Fatalf("empty JWKS wiped the cache: %v", err)
	}
}

func TestNewValidatesConfig(t *testing.T) {
	for _, issuer := range []string{"", "not a url", "ftp://auth.example.com", "https://"} {
		if _, err := New(Config{Issuer: issuer}); err == nil {
			t.Errorf("New accepted issuer %q", issuer)
		}
	}
	c, err := New(Config{Issuer: "https://auth.example.com/"})
	if err != nil {
		t.Fatal(err)
	}
	if c.issuer != "https://auth.example.com" || c.jwksURL != "https://auth.example.com/.well-known/jwks.json" || c.audience != DefaultAudience {
		t.Fatalf("defaults wrong: %+v", c)
	}
}

func TestErrorsAreWrapped(t *testing.T) {
	clk := newClock()
	iss := newFakeIssuer(t, clk)
	key := iss.addKey("k1")
	c := iss.client(clk)
	_, err := c.VerifyToken(context.Background(), iss.token(key, withClaim("iss", "https://evil.example")))
	if err == nil || !strings.Contains(err.Error(), "issuer") {
		t.Fatalf("unhelpful error: %v", err)
	}
	_ = fmt.Sprint(err)
}
