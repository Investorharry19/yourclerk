package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"regexp"
	"time"
)

const (
	// TokenBytes is the amount of randomness in a session token (256 bits).
	TokenBytes = 32

	// AbsoluteTTL is the default absolute session lifetime of a new application
	// (the column default in migration 00005; each application can change it).
	AbsoluteTTL = 30 * 24 * time.Hour
	// IdleTTL is the default idle timeout of a new application (likewise per application).
	IdleTTL = 7 * 24 * time.Hour
)

// NewSessionToken returns a random token for the cookie and its SHA-256 hash
// for the database. It uses crypto/rand, never math/rand.
//
// A fast hash is fine here (unlike for passwords) because the token already
// has 256 bits of entropy, so there is nothing to brute-force.
func NewSessionToken() (token string, hash []byte, err error) {
	b := make([]byte, TokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", nil, fmt.Errorf("generate session token: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	return token, HashToken(token), nil
}

// HashToken returns the SHA-256 hash used to look a token up in the database.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// NewOneTimeToken returns a random single-use token (for email verification and
// password reset links) and its SHA-256 hash for the database. Same strength
// and storage rules as a session token: 256 random bits, only the hash is stored.
func NewOneTimeToken() (token string, hash []byte, err error) {
	return NewSessionToken()
}

// IsWellFormedToken reports whether s has the exact shape of a token made by
// NewSessionToken / NewOneTimeToken, so malformed input is rejected before it
// is hashed or reaches the database.
func IsWellFormedToken(s string) bool { return tokenRE.MatchString(s) }

var tokenRE = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
