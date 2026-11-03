package yourclerk

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// TestServerCompatibility verifies tokens and a JWKS produced by the real
// server code (see testdata/README.md), not by this package's own test signer.
// It catches the two implementations drifting apart on claims or key format.
func TestServerCompatibility(t *testing.T) {
	jwksJSON, err := os.ReadFile("testdata/server_jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	read := func(name string) string {
		b, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(b))
	}
	oldTok, newTok := read("server_token_old_key.txt"), read("server_token_new_key.txt")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON)
	}))
	defer srv.Close()

	clk := newClock()
	clk.Advance(2*time.Minute + 30*time.Second) // 12:02:30, after both tokens were issued

	issuerA := "https://auth.example.com/apps/" + appAID
	c, err := New(Config{Issuer: issuerA, JWKSURL: srv.URL, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	for name, tok := range map[string]string{"old key": oldTok, "rotated key": newTok} {
		claims, err := c.VerifyToken(ctx, tok)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if claims.UserID() != "user-fixture" || claims.SessionID != "sess-fixture" || claims.Issuer != issuerA || claims.ID == "" {
			t.Fatalf("%s: claims = %+v", name, claims)
		}
		if got := claims.ExpiresAt.Sub(claims.IssuedAt); got != time.Hour {
			t.Fatalf("%s: lifetime = %v, want 1h", name, got)
		}
	}

	// The two tokens really came from two different keys.
	if tokenKid(t, oldTok) == tokenKid(t, newTok) {
		t.Fatal("fixtures were signed with the same key; regenerate them")
	}

	// A wrong audience configured on the SDK side must reject the server's tokens.
	strict, _ := New(Config{Issuer: issuerA, Audience: "another-app", JWKSURL: srv.URL, Now: clk.Now})
	if _, err := strict.VerifyToken(ctx, oldTok); !errors.Is(err, ErrWrongAudience) {
		t.Fatalf("wrong audience: %v", err)
	}

	// An hour and a bit later both are expired.
	clk.Advance(2 * time.Hour)
	if _, err := c.VerifyToken(ctx, newTok); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("after expiry: %v", err)
	}
}

// A token minted by application B must fail an SDK configured for application A,
// whichever way the SDK is pointed: at A's keys it is an unknown key, and even
// with B's keys the issuer and audience are wrong.
func TestServerTokensDoNotCrossApplications(t *testing.T) {
	read := func(name string) []byte {
		b, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	serve := func(doc []byte) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(doc) }))
	}
	srvA, srvB := serve(read("server_jwks.json")), serve(read("server_jwks_other_app.json"))
	defer srvA.Close()
	defer srvB.Close()
	tokB := strings.TrimSpace(string(read("server_token_other_app.txt")))
	issuerA, issuerB := "https://auth.example.com/apps/"+appAID, "https://auth.example.com/apps/"+appBID

	clk := newClock()
	clk.Advance(2*time.Minute + 30*time.Second)
	ctx := context.Background()

	// B's token against a client for A, using A's keys.
	a, _ := New(Config{Issuer: issuerA, JWKSURL: srvA.URL, Now: clk.Now})
	if _, err := a.VerifyToken(ctx, tokB); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("B's token with A's keys: %v, want ErrUnknownKey", err)
	}
	// B's token with B's own keys but A's identity: wrong issuer.
	mixed, _ := New(Config{Issuer: issuerA, JWKSURL: srvB.URL, Now: clk.Now})
	if _, err := mixed.VerifyToken(ctx, tokB); !errors.Is(err, ErrWrongIssuer) {
		t.Fatalf("B's token against issuer A: %v, want ErrWrongIssuer", err)
	}
	// Right issuer, wrong audience.
	aud, _ := New(Config{Issuer: issuerB, Audience: appAID, JWKSURL: srvB.URL, Now: clk.Now})
	if _, err := aud.VerifyToken(ctx, tokB); !errors.Is(err, ErrWrongAudience) {
		t.Fatalf("B's token with A's audience: %v, want ErrWrongAudience", err)
	}
	// Control: B's token verifies for B.
	b, _ := New(Config{Issuer: issuerB, JWKSURL: srvB.URL, Now: clk.Now})
	if _, err := b.VerifyToken(ctx, tokB); err != nil {
		t.Fatalf("control: %v", err)
	}
}

const (
	appAID = "0f6c1d2e-7a3b-4c5d-8e9f-a1b2c3d4e5f6"
	appBID = "9b8a7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
)

func tokenKid(t *testing.T, token string) string {
	t.Helper()
	raw, err := strictB64.DecodeString(strings.Split(token, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	i := strings.Index(string(raw), `"kid":"`)
	if i < 0 {
		t.Fatalf("no kid in header %s", raw)
	}
	rest := string(raw)[i+len(`"kid":"`):]
	return rest[:strings.Index(rest, `"`)]
}
