package auth

import (
	"fmt"
)

// Sealer encrypts small blobs with a key derived from SECRET_KEY, for data
// that must be stored but should not be readable from a database dump (the
// queued emails contain live one-time links). It uses a different derived key
// from the signing-key encryption, so the two never share key material.
type Sealer struct{ key []byte }

// NewSealer requires the same minimum secret length as the token service.
func NewSealer(secret string) (*Sealer, error) {
	if len(secret) < minSecretLen {
		return nil, fmt.Errorf("SECRET_KEY must be at least %d characters", minSecretLen)
	}
	return &Sealer{key: deriveKey("email-outbox", secret)}, nil
}

// Seal encrypts plaintext. binding (for example the application id) is
// authenticated but not encrypted: Open with a different binding fails, so a
// blob cannot be moved to another tenant's row and still be read.
func (s *Sealer) Seal(plaintext []byte, binding string) ([]byte, error) {
	return seal(s.key, plaintext, []byte(binding))
}

func (s *Sealer) Open(blob []byte, binding string) ([]byte, error) {
	return open(s.key, blob, []byte(binding))
}
