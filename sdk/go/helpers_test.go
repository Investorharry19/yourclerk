package yourclerk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testAudience = "0f6c1d2e-7a3b-4c5d-8e9f-a1b2c3d4e5f6" // the application id
	testSubject  = "user-1"
)

var rawB64 = base64.RawURLEncoding

// clock is a controllable time source shared by the client and the test issuer.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type testKey struct {
	kid  string
	priv *ecdsa.PrivateKey
}

// fakeIssuer plays the yourclerk server: it serves a JWKS and signs tokens.
type fakeIssuer struct {
	t   *testing.T
	clk *clock
	srv *httptest.Server

	mu      sync.Mutex
	keys    []testKey // published, newest first
	down    bool
	extra   []jwk // extra raw entries to publish (for parsing tests)
	fetches atomic.Int32
}

func newFakeIssuer(t *testing.T, clk *clock) *fakeIssuer {
	t.Helper()
	f := &fakeIssuer{t: t, clk: clk}
	mux := http.NewServeMux()
	mux.HandleFunc("/apps/"+testAudience+"/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		f.fetches.Add(1)
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.down {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		doc := struct {
			Keys []jwk `json:"keys"`
		}{Keys: append([]jwk{}, f.extra...)}
		for _, k := range f.keys {
			doc.Keys = append(doc.Keys, jwkFor(k))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// URL is the application issuer, "<base>/apps/<application id>".
func (f *fakeIssuer) URL() string { return f.srv.URL + "/apps/" + testAudience }

func (f *fakeIssuer) newKey(kid string) testKey {
	f.t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.t.Fatal(err)
	}
	return testKey{kid: kid, priv: priv}
}

// addKey publishes a new key, as a rotation does.
func (f *fakeIssuer) addKey(kid string) testKey {
	k := f.newKey(kid)
	f.mu.Lock()
	f.keys = append([]testKey{k}, f.keys...)
	f.mu.Unlock()
	return k
}

func (f *fakeIssuer) setDown(down bool) {
	f.mu.Lock()
	f.down = down
	f.mu.Unlock()
}

func jwkFor(k testKey) jwk {
	return jwk{
		Kty: "EC", Crv: "P-256", Kid: k.kid, Alg: "ES256", Use: "sig",
		X: rawB64.EncodeToString(k.priv.X.FillBytes(make([]byte, 32))),
		Y: rawB64.EncodeToString(k.priv.Y.FillBytes(make([]byte, 32))),
	}
}

type tokenOpt func(map[string]any)

func withClaim(k string, v any) tokenOpt { return func(m map[string]any) { m[k] = v } }
func without(k string) tokenOpt          { return func(m map[string]any) { delete(m, k) } }

func (f *fakeIssuer) claims(opts ...tokenOpt) map[string]any {
	now := f.clk.Now()
	m := map[string]any{
		"iss": f.URL(),
		"sub": testSubject,
		"aud": testAudience,
		"exp": now.Add(time.Minute).Unix(),
		"nbf": now.Unix(),
		"iat": now.Unix(),
		"jti": "jti-1",
		"sid": "sess-1",
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

// sign mints an ES256 token with the given key and claims.
func sign(t *testing.T, k testKey, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": k.kid})
	payload, _ := json.Marshal(claims)
	input := rawB64.EncodeToString(header) + "." + rawB64.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, k.priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + rawB64.EncodeToString(sig)
}

func (f *fakeIssuer) token(k testKey, opts ...tokenOpt) string {
	return sign(f.t, k, f.claims(opts...))
}

func (f *fakeIssuer) client(clk *clock, mutate ...func(*Config)) *Client {
	f.t.Helper()
	cfg := Config{Issuer: f.URL(), Now: clk.Now}
	for _, m := range mutate {
		m(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		f.t.Fatal(err)
	}
	return c
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
