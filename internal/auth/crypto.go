package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

// deriveEncryptionKey turns SECRET_KEY into a 32-byte AES key. The domain
// prefix means the same secret used for something else yields a different key.
// A production build would use a real KDF (HKDF) and a managed key; this is
// enough to keep private signing keys encrypted at rest in the database.
func deriveEncryptionKey(secret string) []byte {
	sum := sha256.Sum256([]byte("yourclerk/signing-key-encryption/v1\x00" + secret))
	return sum[:]
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// seal encrypts plaintext with AES-256-GCM. The result is nonce || ciphertext.
// aad (the key id) is authenticated but not encrypted, so a private key blob
// cannot be copied onto a different kid without failing to decrypt.
func seal(key, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

func open(key, blob, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(blob) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := blob[:gcm.NonceSize()], blob[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, aad)
}
