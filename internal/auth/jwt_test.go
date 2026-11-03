package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	testIssuer   = "http://issuer.test"
	testAudience = "yourclerk"
	testKID      = "key-1"
)

var testNow = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func goodClaims() Claims {
	return Claims{
		Issuer:    testIssuer,
		Subject:   "user-1",
		Audience:  Audience{testAudience},
		ExpiresAt: NewNumericDate(testNow.Add(time.Minute)),
		NotBefore: NewNumericDate(testNow),
		IssuedAt:  NewNumericDate(testNow),
		ID:        "jti-1",
		SessionID: "sess-1",
	}
}

func keysFor(m map[string]*ecdsa.PrivateKey) KeyFunc {
	return func(kid string) (*ecdsa.PublicKey, error) {
		if k, ok := m[kid]; ok {
			return &k.PublicKey, nil
		}
		return nil, ErrUnknownKey
	}
}

func opts() VerifyOptions {
	return VerifyOptions{Issuer: testIssuer, Audience: testAudience, Now: testNow}
}

// craft assembles a token from raw header and payload JSON with the given signature part.
func craft(header, payload map[string]any, sig string) string {
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	return rawB64.EncodeToString(h) + "." + rawB64.EncodeToString(p) + "." + sig
}

func TestSignAndVerify(t *testing.T) {
	key := mustKey(t)
	token, err := SignES256(testKID, key, goodClaims())
	if err != nil {
		t.Fatal(err)
	}
	claims, err := Verify(token, keysFor(map[string]*ecdsa.PrivateKey{testKID: key}), opts())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != "user-1" || claims.SessionID != "sess-1" || claims.Issuer != testIssuer || !claims.Audience.Contains(testAudience) {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestVerifyRejectsBadTokens(t *testing.T) {
	key := mustKey(t)
	other := mustKey(t)
	keys := keysFor(map[string]*ecdsa.PrivateKey{testKID: key})

	good, err := SignES256(testKID, key, goodClaims())
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(good, ".")

	// Tampered payload: swap the subject but keep the old signature.
	evil := goodClaims()
	evil.Subject = "admin"
	evilPayload, _ := json.Marshal(evil)
	tampered := parts[0] + "." + rawB64.EncodeToString(evilPayload) + "." + parts[2]

	// Signed by a different key but claiming the trusted kid.
	wrongKey, _ := SignES256(testKID, other, goodClaims())

	expired := goodClaims()
	expired.ExpiresAt = NewNumericDate(testNow.Add(-time.Second))
	expiredTok, _ := SignES256(testKID, key, expired)

	notYet := goodClaims()
	notYet.NotBefore = NewNumericDate(testNow.Add(time.Hour))
	notYetTok, _ := SignES256(testKID, key, notYet)

	wrongIss := goodClaims()
	wrongIss.Issuer = "http://evil.test"
	wrongIssTok, _ := SignES256(testKID, key, wrongIss)

	wrongAud := goodClaims()
	wrongAud.Audience = Audience{"someone-else"}
	wrongAudTok, _ := SignES256(testKID, key, wrongAud)

	noExp := goodClaims()
	noExp.ExpiresAt = 0
	noExpTok, _ := SignES256(testKID, key, noExp)

	unknownKid, _ := SignES256("other-kid", key, goodClaims())

	payload := map[string]any{"iss": testIssuer, "aud": testAudience, "sub": "user-1", "exp": testNow.Add(time.Minute).Unix()}

	// Algorithm confusion: HS256 "signed" with the public key bytes as the HMAC secret.
	hmacSigning := rawB64.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT","kid":"key-1"}`)) + "." + rawB64.EncodeToString(mustJSON(payload))
	mac := hmac.New(sha256.New, []byte("public-key-bytes"))
	mac.Write([]byte(hmacSigning))
	hs256 := hmacSigning + "." + rawB64.EncodeToString(mac.Sum(nil))

	tests := []struct {
		name  string
		token string
		want  error
	}{
		{"tampered payload", tampered, ErrInvalidToken},
		{"wrong key", wrongKey, ErrInvalidToken},
		{"expired", expiredTok, ErrTokenExpired},
		{"not yet valid", notYetTok, ErrTokenNotYetValid},
		{"wrong issuer", wrongIssTok, ErrWrongIssuer},
		{"wrong audience", wrongAudTok, ErrWrongAudience},
		{"missing exp", noExpTok, ErrInvalidToken},
		{"unknown kid", unknownKid, ErrUnknownKey},
		{"alg none, empty signature", craft(map[string]any{"alg": "none", "typ": "JWT", "kid": testKID}, payload, ""), ErrInvalidToken},
		{"alg none, signature kept", craft(map[string]any{"alg": "none", "typ": "JWT", "kid": testKID}, payload, parts[2]), ErrInvalidToken},
		{"alg None mixed case", craft(map[string]any{"alg": "None", "kid": testKID}, payload, ""), ErrInvalidToken},
		{"alg HS256 confusion", hs256, ErrInvalidToken},
		{"alg RS256 claimed", craft(map[string]any{"alg": "RS256", "kid": testKID}, payload, parts[2]), ErrInvalidToken},
		{"missing kid", craft(map[string]any{"alg": "ES256"}, payload, parts[2]), ErrInvalidToken},
		{"crit header", craft(map[string]any{"alg": "ES256", "kid": testKID, "crit": []string{"exp"}}, payload, parts[2]), ErrInvalidToken},
		{"empty string", "", ErrInvalidToken},
		{"two parts", parts[0] + "." + parts[1], ErrInvalidToken},
		{"four parts", good + ".extra", ErrInvalidToken},
		{"padded base64", parts[0] + "=." + parts[1] + "." + parts[2], ErrInvalidToken},
		{"garbage", "not.a.jwt", ErrInvalidToken},
		{"short signature", parts[0] + "." + parts[1] + "." + rawB64.EncodeToString([]byte("short")), ErrInvalidToken},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := Verify(tc.token, keys, opts())
			if err == nil {
				t.Fatalf("accepted a bad token, claims = %+v", claims)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func TestVerifyLeewayAndBoundaries(t *testing.T) {
	key := mustKey(t)
	keys := keysFor(map[string]*ecdsa.PrivateKey{testKID: key})

	c := goodClaims()
	c.ExpiresAt = NewNumericDate(testNow)
	tok, _ := SignES256(testKID, key, c)

	// exp == now counts as expired.
	if _, err := Verify(tok, keys, opts()); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("exp == now: got %v, want expired", err)
	}
	// ...unless leeway covers it.
	o := opts()
	o.Leeway = 5 * time.Second
	if _, err := Verify(tok, keys, o); err != nil {
		t.Fatalf("with leeway: %v", err)
	}
}

func TestVerifyRequiresIssuerAndAudience(t *testing.T) {
	key := mustKey(t)
	tok, _ := SignES256(testKID, key, goodClaims())
	keys := keysFor(map[string]*ecdsa.PrivateKey{testKID: key})

	if _, err := Verify(tok, keys, VerifyOptions{Audience: testAudience, Now: testNow}); err == nil {
		t.Fatal("accepted verification with no issuer configured")
	}
	if _, err := Verify(tok, keys, VerifyOptions{Issuer: testIssuer, Now: testNow}); err == nil {
		t.Fatal("accepted verification with no audience configured")
	}
}

func TestAudienceJSON(t *testing.T) {
	var c Claims
	if err := json.Unmarshal([]byte(`{"aud":"a"}`), &c); err != nil || !c.Audience.Contains("a") {
		t.Fatalf("string aud: %v %+v", err, c.Audience)
	}
	if err := json.Unmarshal([]byte(`{"aud":["a","b"]}`), &c); err != nil || !c.Audience.Contains("b") {
		t.Fatalf("array aud: %v %+v", err, c.Audience)
	}
	if err := json.Unmarshal([]byte(`{"aud":5}`), &c); err == nil {
		t.Fatal("accepted numeric aud")
	}
	b, _ := json.Marshal(Claims{Audience: Audience{"only"}})
	if !strings.Contains(string(b), `"aud":"only"`) {
		t.Fatalf("single audience should marshal as a string: %s", b)
	}
}

func TestSignRejectsBadInput(t *testing.T) {
	if _, err := SignES256("", mustKey(t), goodClaims()); err == nil {
		t.Fatal("signed without a kid")
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := SignES256(testKID, p384, goodClaims()); err == nil {
		t.Fatal("signed with a P-384 key")
	}
}
