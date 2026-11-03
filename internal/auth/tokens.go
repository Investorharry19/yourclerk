package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	// DefaultAudience is the "aud" claim until Stage 4 makes it per-application.
	DefaultAudience = "yourclerk"
	// DefaultTokenTTL is the lifetime of an access token.
	DefaultTokenTTL = 60 * time.Second
	// KeyGrace is how long a retired key stays in the JWKS. It must be longer
	// than the token lifetime plus the longest JWKS cache a verifier keeps, so
	// tokens signed just before a rotation still verify.
	KeyGrace = 24 * time.Hour
	// JWKSCacheMaxAge is the Cache-Control max-age of the JWKS, and the default
	// cache lifetime in the SDK.
	JWKSCacheMaxAge = 5 * time.Minute
	// KeyActivationDelay is how long a rotated-in key is published before it
	// signs its first token. It must comfortably exceed JWKSCacheMaxAge, so
	// every verifier has fetched the new key before any token uses it.
	KeyActivationDelay = 10 * time.Minute

	minSecretLen = 32
)

// JWK is one public key in a JSON Web Key Set (RFC 7517 / RFC 7518 for EC keys).
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWKFromPublicKey builds the JWK for an ES256 public key.
func JWKFromPublicKey(kid string, pub *ecdsa.PublicKey) JWK {
	return JWK{
		Kty: "EC",
		Crv: "P-256",
		X:   rawB64.EncodeToString(pub.X.FillBytes(make([]byte, 32))),
		Y:   rawB64.EncodeToString(pub.Y.FillBytes(make([]byte, 32))),
		Kid: kid,
		Alg: AlgES256,
		Use: "sig",
	}
}

// TokenService issues short-lived access tokens and publishes the public keys
// that verify them. Private keys live encrypted in the KeyStore.
type TokenService struct {
	keys     KeyStore
	encKey   []byte
	issuer   string
	audience string
	ttl      time.Duration

	mu    sync.Mutex
	privs map[string]*ecdsa.PrivateKey // decrypted keys by kid
}

// NewTokenService validates its inputs. secret encrypts private keys at rest
// and must be at least 32 characters.
func NewTokenService(keys KeyStore, secret, issuer, audience string, ttl time.Duration) (*TokenService, error) {
	if len(secret) < minSecretLen {
		return nil, fmt.Errorf("SECRET_KEY must be at least %d characters", minSecretLen)
	}
	if issuer == "" {
		return nil, errors.New("issuer is required")
	}
	if audience == "" {
		audience = DefaultAudience
	}
	if ttl <= 0 {
		ttl = DefaultTokenTTL
	}
	return &TokenService{
		keys:     keys,
		encKey:   deriveEncryptionKey(secret),
		issuer:   issuer,
		audience: audience,
		ttl:      ttl,
		privs:    map[string]*ecdsa.PrivateKey{},
	}, nil
}

func (t *TokenService) Issuer() string   { return t.issuer }
func (t *TokenService) Audience() string { return t.audience }
func (t *TokenService) TTL() time.Duration {
	return t.ttl
}

func (t *TokenService) newKeyRecord(now, activeFrom time.Time) (SigningKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return SigningKey{}, fmt.Errorf("generate key: %w", err)
	}
	idBytes := make([]byte, 12)
	if _, err := rand.Read(idBytes); err != nil {
		return SigningKey{}, fmt.Errorf("generate kid: %w", err)
	}
	kid := rawB64.EncodeToString(idBytes)

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return SigningKey{}, err
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return SigningKey{}, err
	}
	sealed, err := seal(t.encKey, privDER, []byte(kid))
	if err != nil {
		return SigningKey{}, err
	}
	return SigningKey{
		KID:                 kid,
		Algorithm:           AlgES256,
		PublicKey:           pubDER,
		PrivateKeyEncrypted: sealed,
		CreatedAt:           now,
		ActiveFrom:          activeFrom,
	}, nil
}

// EnsureKey creates the first signing key if none is active. Safe to call at startup.
func (t *TokenService) EnsureKey(ctx context.Context, now time.Time) error {
	_, err := t.keys.ActiveSigningKey(ctx, now)
	if err == nil {
		return nil
	}
	if !errors.Is(err, ErrNoSigningKey) {
		return err
	}
	rec, err := t.newKeyRecord(now, now) // the very first key signs immediately
	if err != nil {
		return err
	}
	return t.keys.CreateSigningKey(ctx, rec)
}

// Rotate publishes a new signing key now and makes it the signing key after
// delay (use KeyActivationDelay). Until then the current key keeps signing, so
// every verifier gets to cache the new key before a token that needs it exists.
// The old key retires when the new one activates and then stays in the JWKS for
// KeyGrace, so tokens signed just before the switch keep verifying.
func (t *TokenService) Rotate(ctx context.Context, now time.Time, delay time.Duration) (kid string, activeFrom time.Time, err error) {
	if delay < 0 {
		return "", time.Time{}, errors.New("rotate: delay must not be negative")
	}
	activeFrom = now.Add(delay)
	rec, err := t.newKeyRecord(now, activeFrom)
	if err != nil {
		return "", time.Time{}, err
	}
	if err := t.keys.RotateSigningKey(ctx, rec); err != nil {
		return "", time.Time{}, err
	}
	return rec.KID, activeFrom, nil
}

func (t *TokenService) activePrivateKey(ctx context.Context, now time.Time) (string, *ecdsa.PrivateKey, error) {
	rec, err := t.keys.ActiveSigningKey(ctx, now)
	if errors.Is(err, ErrNoSigningKey) {
		if err := t.EnsureKey(ctx, now); err != nil {
			return "", nil, err
		}
		rec, err = t.keys.ActiveSigningKey(ctx, now)
	}
	if err != nil {
		return "", nil, err
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if k, ok := t.privs[rec.KID]; ok {
		return rec.KID, k, nil
	}
	der, err := open(t.encKey, rec.PrivateKeyEncrypted, []byte(rec.KID))
	if err != nil {
		return "", nil, fmt.Errorf("decrypt signing key %s (was SECRET_KEY changed?): %w", rec.KID, err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return "", nil, fmt.Errorf("parse signing key %s: %w", rec.KID, err)
	}
	priv, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return "", nil, fmt.Errorf("signing key %s is not an ECDSA key", rec.KID)
	}
	t.privs[rec.KID] = priv
	return rec.KID, priv, nil
}

// Issue mints an access token for a user's session and returns its expiry.
func (t *TokenService) Issue(ctx context.Context, userID, sessionID string, now time.Time) (string, time.Time, error) {
	kid, priv, err := t.activePrivateKey(ctx, now)
	if err != nil {
		return "", time.Time{}, err
	}
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", time.Time{}, fmt.Errorf("generate jti: %w", err)
	}

	exp := now.Add(t.ttl)
	token, err := SignES256(kid, priv, Claims{
		Issuer:    t.issuer,
		Subject:   userID,
		Audience:  Audience{t.audience},
		ExpiresAt: NewNumericDate(exp),
		NotBefore: NewNumericDate(now),
		IssuedAt:  NewNumericDate(now),
		ID:        rawB64.EncodeToString(jti),
		SessionID: sessionID,
	})
	if err != nil {
		return "", time.Time{}, err
	}
	return token, exp, nil
}

// JWKS returns the public keys verifiers should trust, newest first.
func (t *TokenService) JWKS(ctx context.Context, now time.Time) (JWKS, error) {
	recs, err := t.keys.PublishedSigningKeys(ctx, now.Add(-KeyGrace))
	if err != nil {
		return JWKS{}, err
	}
	out := JWKS{Keys: make([]JWK, 0, len(recs))}
	for _, rec := range recs {
		pub, err := parsePublicKey(rec.PublicKey)
		if err != nil {
			return JWKS{}, fmt.Errorf("parse public key %s: %w", rec.KID, err)
		}
		out.Keys = append(out.Keys, JWKFromPublicKey(rec.KID, pub))
	}
	return out, nil
}

func parsePublicKey(der []byte) (*ecdsa.PublicKey, error) {
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("not an ECDSA P-256 key")
	}
	return pub, nil
}

// Verify checks a token this service issued, using its own published keys.
// It is for the server's own use (tests now, pending-MFA tokens in Stage 7);
// customer backends use the SDK instead.
func (t *TokenService) Verify(ctx context.Context, token string, now time.Time) (*Claims, error) {
	recs, err := t.keys.PublishedSigningKeys(ctx, now.Add(-KeyGrace))
	if err != nil {
		return nil, err
	}
	keyFunc := func(kid string) (*ecdsa.PublicKey, error) {
		for _, rec := range recs {
			if rec.KID == kid {
				return parsePublicKey(rec.PublicKey)
			}
		}
		return nil, ErrUnknownKey
	}
	return Verify(token, keyFunc, VerifyOptions{Issuer: t.issuer, Audience: t.audience, Now: now})
}
