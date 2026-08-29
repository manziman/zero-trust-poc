package identity

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

type rsaJWKS struct {
	Keys []struct {
		KeyType   string `json:"kty"`
		Use       string `json:"use"`
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
		Modulus   string `json:"n"`
		Exponent  string `json:"e"`
		Private   string `json:"d"`
	} `json:"keys"`
}

// ParseRSAJWKS accepts only public, RS256 signing keys with unique key IDs.
func ParseRSAJWKS(wire []byte) (map[string]any, error) {
	var document rsaJWKS
	if err := json.Unmarshal(wire, &document); err != nil {
		return nil, fmt.Errorf("decode JWKS: %w", err)
	}
	keys := make(map[string]any)
	for _, candidate := range document.Keys {
		if candidate.KeyType != "RSA" || candidate.Use != "sig" || candidate.Algorithm != "RS256" || candidate.KeyID == "" || candidate.Private != "" {
			continue
		}
		modulus, err := base64.RawURLEncoding.DecodeString(candidate.Modulus)
		if err != nil {
			return nil, fmt.Errorf("decode modulus for %s: %w", candidate.KeyID, err)
		}
		exponentBytes, err := base64.RawURLEncoding.DecodeString(candidate.Exponent)
		if err != nil {
			return nil, fmt.Errorf("decode exponent for %s: %w", candidate.KeyID, err)
		}
		exponentValue := new(big.Int).SetBytes(exponentBytes)
		if !exponentValue.IsInt64() || exponentValue.Sign() <= 0 {
			return nil, fmt.Errorf("invalid exponent for %s", candidate.KeyID)
		}
		publicKey := &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: int(exponentValue.Int64())}
		if publicKey.N.BitLen() < 2048 || publicKey.E < 3 {
			return nil, fmt.Errorf("weak RSA key %s", candidate.KeyID)
		}
		if _, exists := keys[candidate.KeyID]; exists {
			return nil, fmt.Errorf("duplicate JWKS key ID %s", candidate.KeyID)
		}
		keys[candidate.KeyID] = publicKey
	}
	if len(keys) == 0 {
		return nil, errors.New("JWKS contains no usable RS256 signing keys")
	}
	return keys, nil
}

// RemoteVerifier keeps the last-known-good Keycloak signing set. Refresh
// failures never replace a valid set with empty or malformed data.
type RemoteVerifier struct {
	mu       sync.RWMutex
	Issuer   string
	Audience string
	JWKSURL  string
	Client   *http.Client
	Now      func() time.Time
	Skew     time.Duration
	keys     map[string]any
}

func (v *RemoteVerifier) Refresh(ctx context.Context) error {
	if v.JWKSURL == "" || v.Client == nil {
		return errors.New("JWKS URL and HTTP client are required")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, v.JWKSURL, nil)
	if err != nil {
		return err
	}
	response, err := v.Client.Do(request)
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch JWKS: status %s", response.Status)
	}
	wire, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024+1))
	if err != nil {
		return fmt.Errorf("read JWKS: %w", err)
	}
	if len(wire) > 1024*1024 {
		return errors.New("JWKS exceeds one MiB")
	}
	keys, err := ParseRSAJWKS(wire)
	if err != nil {
		return err
	}
	v.mu.Lock()
	v.keys = keys
	v.mu.Unlock()
	return nil
}

func (v *RemoteVerifier) Verify(compact string) (AccessClaims, error) {
	return v.verifier().Verify(compact)
}

func (v *RemoteVerifier) VerifyNonce(compact, nonce string) (AccessClaims, error) {
	return v.verifier().VerifyNonce(compact, nonce)
}

func (v *RemoteVerifier) verifier() AccessTokenVerifier {
	v.mu.RLock()
	keys := make(map[string]any, len(v.keys))
	for keyID, key := range v.keys {
		keys[keyID] = key
	}
	v.mu.RUnlock()
	return AccessTokenVerifier{
		Issuer: v.Issuer, Audience: v.Audience, Keys: keys, Now: v.Now, Skew: v.Skew,
	}
}
