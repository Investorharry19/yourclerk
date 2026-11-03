package auth

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrNoSigningKey means there is no active (unretired) signing key yet.
var ErrNoSigningKey = errors.New("no active signing key")

// SigningKey is one ES256 key pair as stored in the database.
type SigningKey struct {
	KID                 string
	Algorithm           string
	PublicKey           []byte // DER, PKIX
	PrivateKeyEncrypted []byte // AES-GCM(nonce || ciphertext) of DER PKCS#8
	CreatedAt           time.Time
	// ActiveFrom is when the key starts signing. It is published in the JWKS
	// from CreatedAt, so verifiers can cache it before any token uses it.
	ActiveFrom time.Time
	// RetiredAt is when the key stops signing (nil: not scheduled). It stays
	// in the JWKS for KeyGrace afterwards.
	RetiredAt *time.Time
}

// KeyStore persists signing keys. *store.Store implements it for Postgres and
// MemoryKeyStore implements it for tests.
type KeyStore interface {
	CreateSigningKey(ctx context.Context, k SigningKey) error
	// ActiveSigningKey returns the key that signs at time now: the newest key with
	// ActiveFrom <= now that is not retired by now. ErrNoSigningKey if there is none.
	ActiveSigningKey(ctx context.Context, now time.Time) (SigningKey, error)
	// PublishedSigningKeys returns every key that should appear in the JWKS:
	// active keys plus keys retired after retiredAfter, newest first.
	PublishedSigningKeys(ctx context.Context, retiredAfter time.Time) ([]SigningKey, error)
	// RotateSigningKey schedules every not-yet-retired key to retire at k.ActiveFrom and
	// adds k, atomically. k is published immediately and starts signing at k.ActiveFrom.
	RotateSigningKey(ctx context.Context, k SigningKey) error
}

// MemoryKeyStore is an in-memory KeyStore for tests and experiments.
type MemoryKeyStore struct {
	mu   sync.Mutex
	keys []SigningKey // oldest first
}

func NewMemoryKeyStore() *MemoryKeyStore { return &MemoryKeyStore{} }

func (m *MemoryKeyStore) CreateSigningKey(_ context.Context, k SigningKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys = append(m.keys, k)
	return nil
}

func (m *MemoryKeyStore) ActiveSigningKey(_ context.Context, now time.Time) (SigningKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var best *SigningKey
	for i := range m.keys {
		k := &m.keys[i]
		if k.ActiveFrom.After(now) || (k.RetiredAt != nil && !k.RetiredAt.After(now)) {
			continue
		}
		if best == nil || k.ActiveFrom.After(best.ActiveFrom) || (k.ActiveFrom.Equal(best.ActiveFrom) && k.CreatedAt.After(best.CreatedAt)) {
			best = k
		}
	}
	if best == nil {
		return SigningKey{}, ErrNoSigningKey
	}
	return *best, nil
}

func (m *MemoryKeyStore) PublishedSigningKeys(_ context.Context, retiredAfter time.Time) ([]SigningKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []SigningKey
	for i := len(m.keys) - 1; i >= 0; i-- {
		k := m.keys[i]
		if k.RetiredAt == nil || k.RetiredAt.After(retiredAfter) {
			out = append(out, k)
		}
	}
	return out, nil
}

func (m *MemoryKeyStore) RotateSigningKey(_ context.Context, k SigningKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.keys {
		if m.keys[i].RetiredAt == nil {
			t := k.ActiveFrom
			m.keys[i].RetiredAt = &t
		}
	}
	m.keys = append(m.keys, k)
	return nil
}
