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

	c, err := New(Config{Issuer: "https://auth.example.com", JWKSURL: srv.URL, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	for name, tok := range map[string]string{"old key": oldTok, "rotated key": newTok} {
		claims, err := c.VerifyToken(ctx, tok)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if claims.UserID() != "user-fixture" || claims.SessionID != "sess-fixture" || claims.Issuer != "https://auth.example.com" || claims.ID == "" {
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
	strict, _ := New(Config{Issuer: "https://auth.example.com", Audience: "another-app", JWKSURL: srv.URL, Now: clk.Now})
	if _, err := strict.VerifyToken(ctx, oldTok); !errors.Is(err, ErrWrongAudience) {
		t.Fatalf("wrong audience: %v", err)
	}

	// An hour and a bit later both are expired.
	clk.Advance(2 * time.Hour)
	if _, err := c.VerifyToken(ctx, newTok); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("after expiry: %v", err)
	}
}

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
