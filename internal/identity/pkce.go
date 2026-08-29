package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
)

// PKCE contains the ephemeral proof and CSRF/replay values for one OIDC
// Authorization Code flow. Values are intentionally held in memory only.
type PKCE struct {
	Verifier  string
	Challenge string
	Method    string
	State     string
	Nonce     string
}

// NewPKCE creates an RFC 7636 S256 proof plus independent OIDC state and
// nonce values using the operating system cryptographic random source.
func NewPKCE() (PKCE, error) {
	verifier, err := randomBase64URL(32)
	if err != nil {
		return PKCE{}, err
	}
	state, err := randomBase64URL(32)
	if err != nil {
		return PKCE{}, err
	}
	nonce, err := randomBase64URL(32)
	if err != nil {
		return PKCE{}, err
	}
	digest := sha256.Sum256([]byte(verifier))
	return PKCE{
		Verifier:  verifier,
		Challenge: base64.RawURLEncoding.EncodeToString(digest[:]),
		Method:    "S256",
		State:     state,
		Nonce:     nonce,
	}, nil
}

// ValidateCallback rejects login CSRF and callbacks that do not carry an
// authorization code. State is compared in constant time.
func (p PKCE) ValidateCallback(state, code string) error {
	if p.State == "" || state == "" || subtle.ConstantTimeCompare([]byte(p.State), []byte(state)) != 1 {
		return errors.New("OIDC callback state mismatch")
	}
	if code == "" {
		return errors.New("OIDC callback has no authorization code")
	}
	return nil
}

func randomBase64URL(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}
