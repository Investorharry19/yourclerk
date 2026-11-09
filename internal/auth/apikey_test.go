package auth

import (
	"bytes"
	"strings"
	"testing"
)

func TestKeyFormats(t *testing.T) {
	pk, err := NewPublishableKey()
	if err != nil {
		t.Fatal(err)
	}
	sk, hash, last4, err := NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	dvt, dvtHash, err := NewDeveloperToken()
	if err != nil {
		t.Fatal(err)
	}

	if !IsPublishableKey(pk) || IsSecretKey(pk) || IsDeveloperToken(pk) {
		t.Fatalf("publishable key misclassified: %q", pk)
	}
	if !IsSecretKey(sk) || IsPublishableKey(sk) || IsDeveloperToken(sk) {
		t.Fatalf("secret key misclassified: %q", sk)
	}
	if !IsDeveloperToken(dvt) || IsPublishableKey(dvt) || IsSecretKey(dvt) {
		t.Fatalf("developer token misclassified: %q", dvt)
	}

	if !strings.HasSuffix(sk, last4) || len(last4) != 4 {
		t.Fatalf("last4 = %q for %q", last4, sk)
	}
	if !bytes.Equal(hash, HashSecretKey(sk)) || bytes.Contains(hash, []byte(sk)) {
		t.Fatal("secret key hash is wrong or contains the key")
	}
	if !bytes.Equal(dvtHash, HashToken(dvt)) {
		t.Fatal("developer token hash is wrong")
	}
	if len(hash) != 32 {
		t.Fatalf("hash length = %d", len(hash))
	}
}

func TestKeysAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 500; i++ {
		pk, _ := NewPublishableKey()
		sk, _, _, _ := NewSecretKey()
		dvt, _, _ := NewDeveloperToken()
		for _, k := range []string{pk, sk, dvt} {
			if seen[k] {
				t.Fatalf("duplicate credential generated: %s", k)
			}
			seen[k] = true
		}
	}
}

func TestKeyFormatRejectsJunk(t *testing.T) {
	pk, _ := NewPublishableKey()
	sk, _, _, _ := NewSecretKey()
	for _, bad := range []string{
		"", "pk_live_", "sk_live_", "pk_test_" + strings.Repeat("a", 24),
		pk + "x", pk[:len(pk)-1], " " + pk, pk + "\n", strings.ToUpper(pk),
		"pk_live_" + strings.Repeat("!", 24),
		sk + "x", sk[:len(sk)-1],
		"pk_live_" + strings.Repeat("a", 24) + "'; DROP TABLE users;--",
	} {
		if IsPublishableKey(bad) || IsSecretKey(bad) || IsDeveloperToken(bad) {
			t.Errorf("accepted junk %q", bad)
		}
	}
}

func TestCookieSuffix(t *testing.T) {
	pk, _ := NewPublishableKey()
	s := CookieSuffix(pk)
	if len(s) != 10 || !strings.HasPrefix(pk, PublishableKeyPrefix+s) {
		t.Fatalf("suffix = %q for %q", s, pk)
	}
	if CookieSuffix("short") == "" {
		t.Fatal("empty suffix for malformed key")
	}
	// Cookie names allow letters, digits, '-' and '_'; make sure that holds.
	for i := 0; i < 200; i++ {
		k, _ := NewPublishableKey()
		for _, r := range CookieSuffix(k) {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				t.Fatalf("suffix %q has character %q", CookieSuffix(k), r)
			}
		}
	}
}

func TestOneTimeTokens(t *testing.T) {
	tok, hash, err := NewOneTimeToken()
	if err != nil {
		t.Fatal(err)
	}
	if !IsWellFormedToken(tok) || !bytes.Equal(hash, HashToken(tok)) || len(hash) != 32 {
		t.Fatalf("token %q / hash wrong", tok)
	}
	if tok2, _, _ := NewOneTimeToken(); tok2 == tok {
		t.Fatal("duplicate token")
	}
	for _, bad := range []string{"", "short", tok + "x", tok[:42], " " + tok, tok + "\n", strings.Repeat("!", 43)} {
		if IsWellFormedToken(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestSealer(t *testing.T) {
	if _, err := NewSealer("short"); err == nil {
		t.Fatal("accepted a short secret")
	}
	s, _ := NewSealer("sealer-secret-sealer-secret-1234567")
	blob, err := s.Seal([]byte("hello link"), "app-1")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, []byte("hello")) {
		t.Fatal("plaintext visible in sealed blob")
	}
	if got, err := s.Open(blob, "app-1"); err != nil || string(got) != "hello link" {
		t.Fatalf("open: %q %v", got, err)
	}
	if _, err := s.Open(blob, "app-2"); err == nil {
		t.Fatal("opened under another binding")
	}
	other, _ := NewSealer("another-secret-another-secret-12345")
	if _, err := other.Open(blob, "app-1"); err == nil {
		t.Fatal("opened with another secret")
	}
	// The sealer's key is not the signing-key encryption key.
	if bytes.Equal(s.key, deriveEncryptionKey("sealer-secret-sealer-secret-1234567")) {
		t.Fatal("sealer shares the signing-key encryption key")
	}
}
