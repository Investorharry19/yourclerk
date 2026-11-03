package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

// AlgES256 is the only signing algorithm this service issues or accepts.
// Verification never trusts the algorithm named in a token header: anything
// other than this exact value (including "none" and "HS256") is rejected.
const AlgES256 = "ES256"

var (
	// ErrInvalidToken covers malformed tokens, bad signatures and wrong algorithms.
	ErrInvalidToken = errors.New("invalid token")
	// ErrTokenExpired means exp has passed.
	ErrTokenExpired = errors.New("token expired")
	// ErrTokenNotYetValid means nbf is in the future.
	ErrTokenNotYetValid = errors.New("token not yet valid")
	// ErrWrongIssuer and ErrWrongAudience mean the token was meant for someone else.
	ErrWrongIssuer   = errors.New("wrong token issuer")
	ErrWrongAudience = errors.New("wrong token audience")
	// ErrUnknownKey means the token's kid is not one of our published keys.
	ErrUnknownKey = errors.New("unknown signing key")
)

var rawB64 = base64.RawURLEncoding

// strictB64 rejects padding and non-canonical encodings when decoding.
var strictB64 = base64.RawURLEncoding.Strict()

// NumericDate is a JWT time: whole seconds since the Unix epoch.
// It accepts fractional values when parsing, as the RFC allows.
type NumericDate int64

func NewNumericDate(t time.Time) NumericDate { return NumericDate(t.Unix()) }

func (n NumericDate) Time() time.Time { return time.Unix(int64(n), 0).UTC() }

func (n *NumericDate) UnmarshalJSON(b []byte) error {
	var f float64
	if err := json.Unmarshal(b, &f); err != nil {
		return err
	}
	if math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > 1<<53 {
		return errors.New("invalid numeric date")
	}
	*n = NumericDate(math.Floor(f))
	return nil
}

// Audience is the "aud" claim, which JSON allows to be a string or an array.
type Audience []string

func (a Audience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
}

func (a *Audience) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = Audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return errors.New("aud must be a string or an array of strings")
	}
	*a = many
	return nil
}

func (a Audience) Contains(s string) bool {
	for _, v := range a {
		if v == s {
			return true
		}
	}
	return false
}

// Claims are the registered claims plus sid (the session this token came from).
type Claims struct {
	Issuer    string      `json:"iss"`
	Subject   string      `json:"sub"`
	Audience  Audience    `json:"aud"`
	ExpiresAt NumericDate `json:"exp"`
	NotBefore NumericDate `json:"nbf,omitempty"`
	IssuedAt  NumericDate `json:"iat,omitempty"`
	ID        string      `json:"jti,omitempty"`
	SessionID string      `json:"sid,omitempty"`
}

// SignES256 signs claims with an ECDSA P-256 key and returns a compact JWT.
func SignES256(kid string, key *ecdsa.PrivateKey, claims Claims) (string, error) {
	if kid == "" {
		return "", errors.New("sign token: kid is required")
	}
	if key == nil || key.Curve != elliptic.P256() {
		return "", errors.New("sign token: key must be an ECDSA P-256 private key")
	}

	header, err := json.Marshal(map[string]string{"alg": AlgES256, "typ": "JWT", "kid": kid})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	signingInput := rawB64.EncodeToString(header) + "." + rawB64.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	// JWS wants the raw r||s concatenation, 32 bytes each, not ASN.1.
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signingInput + "." + rawB64.EncodeToString(sig), nil
}

// KeyFunc returns the public key for a kid, or an error wrapping ErrUnknownKey.
type KeyFunc func(kid string) (*ecdsa.PublicKey, error)

// VerifyOptions say what a valid token must look like. Issuer and Audience are
// required: skipping those checks is one of the classic JWT mistakes.
type VerifyOptions struct {
	Issuer   string
	Audience string
	Now      time.Time     // zero means time.Now()
	Leeway   time.Duration // tolerated clock skew
}

// Verify checks a compact JWT and returns its claims. Order matters: the
// signature is checked before any claim is trusted.
func Verify(token string, keyFunc KeyFunc, opts VerifyOptions) (*Claims, error) {
	if opts.Issuer == "" || opts.Audience == "" {
		return nil, errors.New("verify token: issuer and audience are required")
	}

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
	if header.Alg != AlgES256 {
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

	pub, err := keyFunc(header.Kid)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return nil, fmt.Errorf("%w: bad signature", ErrInvalidToken)
	}

	payload, err := strictB64.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: bad payload encoding", ErrInvalidToken)
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: bad claims", ErrInvalidToken)
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	if claims.ExpiresAt == 0 {
		return nil, fmt.Errorf("%w: missing exp", ErrInvalidToken)
	}
	if !now.Before(claims.ExpiresAt.Time().Add(opts.Leeway)) {
		return nil, ErrTokenExpired
	}
	if claims.NotBefore != 0 && now.Add(opts.Leeway).Before(claims.NotBefore.Time()) {
		return nil, ErrTokenNotYetValid
	}
	if claims.Issuer != opts.Issuer {
		return nil, ErrWrongIssuer
	}
	if !claims.Audience.Contains(opts.Audience) {
		return nil, ErrWrongAudience
	}
	return &claims, nil
}
