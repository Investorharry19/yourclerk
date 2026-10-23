// Package password hashes and verifies passwords with Argon2id.
//
// Hashes are stored as a single self-describing string:
//
//	$argon2id$v=19$m=19456,t=2,p=1$<salt>$<key>
//
// The parameters live inside the string, so you can raise them later and
// old hashes keep verifying. The defaults follow the OWASP Password Storage
// Cheat Sheet (m=19 MiB, t=2, p=1); re-check that page before launch.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	memoryKiB   uint32 = 19 * 1024
	iterations  uint32 = 2
	parallelism uint8  = 1
	saltLen            = 16
	keyLen             = 32

	// Upper bounds accepted when parsing a stored hash, so a corrupted row
	// cannot make us allocate gigabytes.
	maxMemoryKiB   = 256 * 1024
	maxIterations  = 10
	maxParallelism = 16
)

var (
	// ErrInvalidHash means the stored string is not a hash we understand.
	ErrInvalidHash = errors.New("password: invalid encoded hash")

	b64 = base64.RawStdEncoding

	// dummyHash is verified against when a login names an unknown user, so
	// "no such user" costs the same time as "wrong password".
	dummyHash = mustHash("not-a-real-password")
)

// Hash returns an encoded Argon2id hash of plain with a fresh random salt.
func Hash(plain string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	key := argon2.IDKey([]byte(plain), salt, iterations, memoryKiB, parallelism, keyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memoryKiB, iterations, parallelism,
		b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// Verify reports whether plain matches the encoded hash. It returns an error
// only when the encoded hash itself is malformed.
func Verify(plain, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return false, ErrInvalidHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, ErrInvalidHash
	}

	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false, ErrInvalidHash
	}
	if m == 0 || m > maxMemoryKiB || t == 0 || t > maxIterations || p == 0 || p > maxParallelism {
		return false, ErrInvalidHash
	}

	salt, err := b64.DecodeString(parts[4])
	if err != nil || len(salt) == 0 {
		return false, ErrInvalidHash
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false, ErrInvalidHash
	}

	got := argon2.IDKey([]byte(plain), salt, t, m, p, uint32(len(want)))
	// Constant-time comparison: == on secrets can leak how many leading bytes matched.
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// DummyVerify burns the same CPU time as a real Verify. Call it when the
// user does not exist so response time does not reveal that.
func DummyVerify(plain string) {
	_, _ = Verify(plain, dummyHash)
}

func mustHash(plain string) string {
	h, err := Hash(plain)
	if err != nil {
		panic(err)
	}
	return h
}
