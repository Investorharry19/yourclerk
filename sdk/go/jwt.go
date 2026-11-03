package yourclerk

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
	"time"
)

// Errors returned by VerifyToken. Use errors.Is to test for them.
var (
	// ErrInvalidToken covers malformed tokens, bad signatures and wrong algorithms.
	ErrInvalidToken = errors.New("yourclerk: invalid token")
	// ErrTokenExpired means the token's exp has passed.
	ErrTokenExpired = errors.New("yourclerk: token expired")
	// ErrTokenNotYetValid means the token's nbf is in the future.
	ErrTokenNotYetValid = errors.New("yourclerk: token not yet valid")
	// ErrWrongIssuer means the token was issued by someone other than the configured issuer.
	ErrWrongIssuer = errors.New("yourclerk: wrong token issuer")
	// ErrWrongAudience means the token was not meant for the configured audience.
	ErrWrongAudience = errors.New("yourclerk: wrong token audience")
	// ErrUnknownKey means the token names a signing key that is not in the issuer's JWKS.
	ErrUnknownKey = errors.New("yourclerk: unknown signing key")
	// ErrJWKSUnavailable means the public keys could not be fetched and none are cached.
	ErrJWKSUnavailable = errors.New("yourclerk: signing keys unavailable")
)

const algES256 = "ES256"

var strictB64 = base64.RawURLEncoding.Strict()

// numericDate is a JWT time in seconds since the Unix epoch; fractions are accepted.
type numericDate int64

func (n *numericDate) UnmarshalJSON(b []byte) error {
	var f float64
	if err := json.Unmarshal(b, &f); err != nil {
		return err
	}
	if math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > 1<<53 {
		return errors.New("invalid numeric date")
	}
	*n = numericDate(math.Floor(f))
	return nil
}

// audience is the "aud" claim, which may be a string or an array of strings.
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return errors.New("aud must be a string or an array of strings")
	}
	*a = many
	return nil
}

func (a audience) contains(s string) bool {
	for _, v := range a {
		if v == s {
			return true
		}
	}
	return false
}

// Claims are the verified contents of an access token.
type Claims struct {
	// Subject is the user ID ("sub").
	Subject string
	// SessionID is the session the token was minted from ("sid").
	SessionID string
	// Issuer ("iss") and Audience ("aud") have already been checked.
	Issuer   string
	Audience []string
	// ID is the unique token ID ("jti").
	ID        string
	IssuedAt  time.Time
	NotBefore time.Time
	ExpiresAt time.Time
}

// UserID returns the signed-in user's ID.
func (c *Claims) UserID() string { return c.Subject }

type wireClaims struct {
	Issuer    string      `json:"iss"`
	Subject   string      `json:"sub"`
	Audience  audience    `json:"aud"`
	ExpiresAt numericDate `json:"exp"`
	NotBefore numericDate `json:"nbf"`
	IssuedAt  numericDate `json:"iat"`
	ID        string      `json:"jti"`
	SessionID string      `json:"sid"`
}

// verifyJWT checks a compact ES256 JWT. The signature is verified before any
// claim is trusted, and the algorithm in the header is never trusted: only an
// exact "ES256" is accepted, so "none" and algorithm-confusion tricks fail.
func verifyJWT(token string, keyFor func(kid string) (*ecdsa.PublicKey, error), issuer, aud string, now time.Time, leeway time.Duration) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: expected 3 parts", ErrInvalidToken)
	}

	headerBytes, err := strictB64.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: bad header encoding", ErrInvalidToken)
	}
	var header struct {
		Alg  string          `json:"alg"`
		Kid  string          `json:"kid"`
		Crit json.RawMessage `json:"crit"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("%w: bad header", ErrInvalidToken)
	}
	if header.Alg != algES256 {
		return nil, fmt.Errorf("%w: unsupported alg", ErrInvalidToken)
	}
	if len(header.Crit) > 0 {
		return nil, fmt.Errorf("%w: unsupported critical header", ErrInvalidToken)
	}
	if header.Kid == "" {
		return nil, fmt.Errorf("%w: missing kid", ErrInvalidToken)
	}

	sig, err := strictB64.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return nil, fmt.Errorf("%w: bad signature encoding", ErrInvalidToken)
	}

	pub, err := keyFor(header.Kid)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return nil, fmt.Errorf("%w: bad signature", ErrInvalidToken)
	}

	payload, err := strictB64.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: bad payload encoding", ErrInvalidToken)
	}
	var w wireClaims
	if err := json.Unmarshal(payload, &w); err != nil {
		return nil, fmt.Errorf("%w: bad claims", ErrInvalidToken)
	}

	if w.ExpiresAt == 0 {
		return nil, fmt.Errorf("%w: missing exp", ErrInvalidToken)
	}
	exp := time.Unix(int64(w.ExpiresAt), 0)
	if !now.Before(exp.Add(leeway)) {
		return nil, ErrTokenExpired
	}
	if w.NotBefore != 0 && now.Add(leeway).Before(time.Unix(int64(w.NotBefore), 0)) {
		return nil, ErrTokenNotYetValid
	}
	if w.Issuer != issuer {
		return nil, ErrWrongIssuer
	}
	if !w.Audience.contains(aud) {
		return nil, ErrWrongAudience
	}
	if w.Subject == "" {
		return nil, fmt.Errorf("%w: missing sub", ErrInvalidToken)
	}

	c := &Claims{
		Subject:   w.Subject,
		SessionID: w.SessionID,
		Issuer:    w.Issuer,
		Audience:  []string(w.Audience),
		ID:        w.ID,
		ExpiresAt: exp.UTC(),
	}
	if w.IssuedAt != 0 {
		c.IssuedAt = time.Unix(int64(w.IssuedAt), 0).UTC()
	}
	if w.NotBefore != 0 {
		c.NotBefore = time.Unix(int64(w.NotBefore), 0).UTC()
	}
	return c, nil
}
