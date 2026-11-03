package auth

import (
	"crypto/rand"
	"fmt"
	"regexp"
	"time"
)

// Key formats. The prefix says what a credential is, so a secret pasted into
// the wrong place is recognised (and rejected) immediately, and so secret
// scanners can spot a leaked key.
//
//	pk_live_<24 chars>   publishable key: identifies an application, safe in browsers
//	sk_live_<43 chars>   secret key: authorises a developer's server, never in browsers
//	dvt_<43 chars>       developer token: a dashboard sign-in for the platform API
const (
	PublishableKeyPrefix = "pk_live_"
	SecretKeyPrefix      = "sk_live_"
	DeveloperTokenPrefix = "dvt_"

	// DeveloperSessionTTL is how long a developer sign-in lasts.
	DeveloperSessionTTL = 7 * 24 * time.Hour
)

var (
	publishableKeyRE = regexp.MustCompile(`^pk_live_[A-Za-z0-9_-]{24}$`)
	secretKeyRE      = regexp.MustCompile(`^sk_live_[A-Za-z0-9_-]{43}$`)
	developerTokenRE = regexp.MustCompile(`^dvt_[A-Za-z0-9_-]{43}$`)
)

func randomString(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}
	return rawB64.EncodeToString(b), nil
}

// NewPublishableKey returns a new publishable key (144 random bits).
func NewPublishableKey() (string, error) {
	r, err := randomString(18)
	if err != nil {
		return "", err
	}
	return PublishableKeyPrefix + r, nil
}

// NewSecretKey returns a new secret key (256 random bits), the SHA-256 hash to
// store, and the last four characters to show in a dashboard. The key itself
// must be shown to the developer once and never stored.
//
// A fast hash is right here, as for session tokens: the key already has 256
// bits of entropy, so there is nothing to brute-force.
func NewSecretKey() (key string, hash []byte, last4 string, err error) {
	r, err := randomString(32)
	if err != nil {
		return "", nil, "", err
	}
	key = SecretKeyPrefix + r
	return key, HashToken(key), key[len(key)-4:], nil
}

// NewDeveloperToken returns a developer sign-in token and its hash.
func NewDeveloperToken() (token string, hash []byte, err error) {
	r, err := randomString(32)
	if err != nil {
		return "", nil, err
	}
	token = DeveloperTokenPrefix + r
	return token, HashToken(token), nil
}

// HashSecretKey returns the hash under which a secret key is stored and looked up.
func HashSecretKey(key string) []byte { return HashToken(key) }

// IsPublishableKey, IsSecretKey and IsDeveloperToken check the exact format, so
// malformed input is rejected before it reaches the database.
func IsPublishableKey(s string) bool { return publishableKeyRE.MatchString(s) }
func IsSecretKey(s string) bool      { return secretKeyRE.MatchString(s) }
func IsDeveloperToken(s string) bool { return developerTokenRE.MatchString(s) }

// CookieSuffix returns a short, stable, per-application piece of the
// publishable key. It lets one browser hold sessions for several applications
// on the same host without their cookies colliding.
func CookieSuffix(publishableKey string) string {
	const n = 10
	if len(publishableKey) < len(PublishableKeyPrefix)+n {
		return "x"
	}
	return publishableKey[len(PublishableKeyPrefix) : len(PublishableKeyPrefix)+n]
}
