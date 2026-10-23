package password

import (
	"errors"
	"strings"
	"testing"
)

func TestHashAndVerify(t *testing.T) {
	tests := []struct {
		name  string
		plain string
		try   string
		want  bool
	}{
		{"correct", "correct horse battery", "correct horse battery", true},
		{"wrong", "correct horse battery", "Correct horse battery", false},
		{"empty attempt", "correct horse battery", "", false},
		{"unicode", "pässwörd-日本語", "pässwörd-日本語", true},
		{"prefix is not enough", "longpassword", "long", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, err := Hash(tc.plain)
			if err != nil {
				t.Fatalf("Hash: %v", err)
			}
			got, err := Verify(tc.try, h)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if got != tc.want {
				t.Fatalf("Verify = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestHashFormatAndSalt(t *testing.T) {
	a, _ := Hash("same password")
	b, _ := Hash("same password")

	if !strings.HasPrefix(a, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("unexpected format: %s", a)
	}
	if strings.Contains(a, "same password") {
		t.Fatal("hash contains the plain password")
	}
	if a == b {
		t.Fatal("two hashes of the same password are identical: salt is not random")
	}
}

func TestVerifyMalformed(t *testing.T) {
	tests := []string{
		"",
		"plaintext",
		"$argon2i$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$a2V5",
		"$argon2id$v=18$m=19456,t=2,p=1$c2FsdHNhbHQ$a2V5",
		"$argon2id$v=19$m=999999999,t=2,p=1$c2FsdHNhbHQ$a2V5",
		"$argon2id$v=19$m=19456,t=0,p=1$c2FsdHNhbHQ$a2V5",
		"$argon2id$v=19$m=19456,t=2,p=1$!!!$a2V5",
		"$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ",
	}
	for _, enc := range tests {
		ok, err := Verify("x", enc)
		if ok || !errors.Is(err, ErrInvalidHash) {
			t.Errorf("Verify(%q) = %v, %v; want false, ErrInvalidHash", enc, ok, err)
		}
	}
}

func TestDummyVerifyDoesNotPanic(t *testing.T) {
	DummyVerify("anything")
}
