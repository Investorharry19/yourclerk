package auth

import (
	"bytes"
	"testing"
)

func TestNewSessionToken(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		token, hash, err := NewSessionToken()
		if err != nil {
			t.Fatal(err)
		}
		if len(token) != 43 { // 32 bytes, unpadded base64url
			t.Fatalf("token length = %d, want 43", len(token))
		}
		if len(hash) != 32 {
			t.Fatalf("hash length = %d, want 32", len(hash))
		}
		if bytes.Contains(hash, []byte(token)) {
			t.Fatal("hash contains the raw token")
		}
		if !bytes.Equal(hash, HashToken(token)) {
			t.Fatal("HashToken is not deterministic")
		}
		if seen[token] {
			t.Fatal("duplicate token generated")
		}
		seen[token] = true
	}
}
