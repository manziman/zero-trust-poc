package identity

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
)

func TestParseRSAJWKSReturnsExplicitSigningKeys(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	exponent := big.NewInt(int64(privateKey.PublicKey.E)).Bytes()
	wire, err := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "current",
		"n": base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(exponent),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := ParseRSAJWKS(wire)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := keys["current"].(*rsa.PublicKey)
	if !ok || key.E != privateKey.PublicKey.E || key.N.Cmp(privateKey.PublicKey.N) != 0 {
		t.Fatalf("parsed key = %#v", keys["current"])
	}
}
