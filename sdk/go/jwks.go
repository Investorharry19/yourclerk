package yourclerk

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
)

const maxJWKSBytes = 1 << 20

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

// fetchJWKS downloads and parses the issuer's public keys. Keys that are not
// usable ES256 signing keys are skipped; if none are usable it is an error, so
// a broken response can never wipe a good cache.
func fetchJWKS(ctx context.Context, client *http.Client, url string) (map[string]*ecdsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks: unexpected status %d", resp.StatusCode)
	}

	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJWKSBytes)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("jwks: bad json: %w", err)
	}

	keys := make(map[string]*ecdsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		pub, ok := k.publicKey()
		if !ok {
			continue
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("jwks: no usable ES256 keys")
	}
	return keys, nil
}

func (k jwk) publicKey() (*ecdsa.PublicKey, bool) {
	if k.Kid == "" || k.Kty != "EC" || k.Crv != "P-256" {
		return nil, false
	}
	if k.Alg != "" && k.Alg != algES256 {
		return nil, false
	}
	if k.Use != "" && k.Use != "sig" {
		return nil, false
	}
	x, err := strictB64.DecodeString(k.X)
	if err != nil || len(x) != 32 {
		return nil, false
	}
	y, err := strictB64.DecodeString(k.Y)
	if err != nil || len(y) != 32 {
		return nil, false
	}
	// ecdh validates that the point is actually on the P-256 curve.
	point := append(append([]byte{4}, x...), y...)
	if _, err := ecdh.P256().NewPublicKey(point); err != nil {
		return nil, false
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}, true
}
