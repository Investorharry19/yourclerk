// Package yourclerk verifies access tokens issued by a yourclerk service.
//
// A Client downloads the issuer's public keys (JWKS) once, caches them, and
// checks token signatures locally. There is no shared secret, and no request
// to the issuer on the hot path: it is contacted only when the cache is older
// than CacheTTL or a token names a key it has not seen (for example after a
// key rotation).
package yourclerk

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Config configures a Client. Only Issuer is required.
type Config struct {
	// Issuer is your application's issuer URL, shown as "issuer" in the dashboard
	// and the API: "<service base URL>/apps/<application id>", for example
	// "https://auth.example.com/apps/0f6c1d2e-7a3b-4c5d-8e9f-a1b2c3d4e5f6".
	// Tokens whose "iss" differs are rejected, so tokens of other applications fail.
	Issuer string
	// Audience is the expected "aud", which is the application id. It is taken
	// from the Issuer URL when that ends in /apps/<id>; set it only for other shapes.
	Audience string
	// JWKSURL overrides where keys are fetched from. Defaults to
	// Issuer + "/.well-known/jwks.json".
	JWKSURL string
	// HTTPClient is used to fetch keys. Defaults to a client with a 5s timeout.
	HTTPClient *http.Client
	// CacheTTL is how long fetched keys are trusted before a refresh. Default 5m.
	CacheTTL time.Duration
	// MinRefreshInterval is the shortest gap between key fetches, so a flood
	// of tokens with unknown key IDs cannot make you hammer the issuer. Default 10s.
	MinRefreshInterval time.Duration
	// Leeway tolerates clock skew between servers when checking exp and nbf. Default 5s.
	Leeway time.Duration
	// Now overrides the clock (for tests). Defaults to time.Now.
	Now func() time.Time
	// OnError, if set, is called with the reason each time RequireAuth rejects
	// a request. Clients only ever see a generic message; log the detail here.
	OnError func(r *http.Request, err error)
}

// Client verifies tokens. It is safe for concurrent use.
type Client struct {
	issuer   string
	audience string
	jwksURL  string
	http     *http.Client
	ttl      time.Duration
	minGap   time.Duration
	leeway   time.Duration
	now      func() time.Time
	onError  func(*http.Request, error)

	mu          sync.RWMutex
	keys        map[string]*ecdsa.PublicKey
	fetchedAt   time.Time
	fetchMu     sync.Mutex // serialises refreshes
	lastAttempt time.Time  // guarded by fetchMu
}

// New validates cfg and returns a Client. It does not contact the issuer;
// keys are fetched on first use.
func New(cfg Config) (*Client, error) {
	issuer := strings.TrimRight(cfg.Issuer, "/")
	if issuer == "" {
		return nil, errors.New("yourclerk: Config.Issuer is required")
	}
	u, err := url.Parse(issuer)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("yourclerk: Config.Issuer %q is not a valid http(s) URL", cfg.Issuer)
	}

	c := &Client{
		issuer:   issuer,
		audience: cfg.Audience,
		jwksURL:  cfg.JWKSURL,
		http:     cfg.HTTPClient,
		ttl:      cfg.CacheTTL,
		minGap:   cfg.MinRefreshInterval,
		leeway:   cfg.Leeway,
		now:      cfg.Now,
		onError:  cfg.OnError,
	}
	if c.audience == "" {
		// ".../apps/<application id>": the id is the audience.
		segs := strings.Split(strings.Trim(u.Path, "/"), "/")
		if len(segs) < 2 || segs[len(segs)-2] != "apps" || segs[len(segs)-1] == "" {
			return nil, fmt.Errorf("yourclerk: Config.Audience is required unless Config.Issuer ends in /apps/<application id> (got %q)", cfg.Issuer)
		}
		c.audience = segs[len(segs)-1]
	}
	if c.jwksURL == "" {
		c.jwksURL = issuer + "/.well-known/jwks.json"
	}
	if c.http == nil {
		c.http = &http.Client{Timeout: 5 * time.Second}
	}
	if c.ttl <= 0 {
		c.ttl = 5 * time.Minute
	}
	if c.minGap <= 0 {
		c.minGap = 10 * time.Second
	}
	if c.leeway == 0 {
		c.leeway = 5 * time.Second
	}
	if c.leeway < 0 {
		c.leeway = 0
	}
	if c.now == nil {
		c.now = time.Now
	}
	return c, nil
}

// VerifyToken checks the signature, expiry, issuer and audience of an access
// token and returns its claims.
func (c *Client) VerifyToken(ctx context.Context, token string) (*Claims, error) {
	return verifyJWT(token, func(kid string) (*ecdsa.PublicKey, error) {
		return c.key(ctx, kid)
	}, c.issuer, c.audience, c.now(), c.leeway)
}

// lookup returns the cached key and whether the cache is still fresh.
func (c *Client) lookup(kid string) (key *ecdsa.PublicKey, fresh bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.keys == nil {
		return nil, false
	}
	return c.keys[kid], c.now().Sub(c.fetchedAt) < c.ttl
}

func (c *Client) key(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	// Hot path: fresh cache and known key. No network, one read lock.
	if k, fresh := c.lookup(kid); k != nil && fresh {
		return k, nil
	}

	c.fetchMu.Lock()
	defer c.fetchMu.Unlock()

	// Another goroutine may have refreshed while we waited for the lock.
	if k, fresh := c.lookup(kid); k != nil && fresh {
		return k, nil
	}

	now := c.now()
	if c.lastAttempt.IsZero() || now.Sub(c.lastAttempt) >= c.minGap {
		c.lastAttempt = now
		keys, err := fetchJWKS(ctx, c.http, c.jwksURL)
		if err == nil {
			c.mu.Lock()
			c.keys, c.fetchedAt = keys, now
			c.mu.Unlock()
			if k, ok := keys[kid]; ok {
				return k, nil
			}
			return nil, ErrUnknownKey
		}
		// Fetch failed: fall through and serve from the stale cache if we can.
		if k, _ := c.lookup(kid); k != nil {
			return k, nil
		}
		if c.hasKeys() {
			return nil, ErrUnknownKey
		}
		return nil, fmt.Errorf("%w: %v", ErrJWKSUnavailable, err)
	}

	// Too soon to ask again. A stale-but-known key is still good; an unknown one is not.
	if k, _ := c.lookup(kid); k != nil {
		return k, nil
	}
	if c.hasKeys() {
		return nil, ErrUnknownKey
	}
	return nil, ErrJWKSUnavailable
}

func (c *Client) hasKeys() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.keys != nil
}
