package identity

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// AccessClaims is the small, typed subset of Keycloak access-token claims
// used to derive Custody subject and workload identities.
type AccessClaims struct {
	Subject  string
	ClientID string
	Scopes   []string
	IssuedAt time.Time
	Expires  time.Time
	Nonce    string
}

// AccessTokenVerifier validates a Keycloak RS256 access token against a
// pinned issuer, audience, and explicit set of trusted key IDs.
type AccessTokenVerifier struct {
	Issuer   string
	Audience string
	Keys     map[string]any
	Now      func() time.Time
	Skew     time.Duration
}

// Verify rejects token/profile substitution before verifying the signature
// and registered claims. Identity is returned only from authenticated claims.
func (v AccessTokenVerifier) Verify(compact string) (AccessClaims, error) {
	if compact == "" || len(compact) > 16*1024 {
		return AccessClaims{}, errors.New("access token size is invalid")
	}
	if v.Issuer == "" || v.Audience == "" || v.Now == nil || len(v.Keys) == 0 {
		return AccessClaims{}, errors.New("access-token verifier configuration is incomplete")
	}

	message, err := jws.Parse([]byte(compact))
	if err != nil || len(message.Signatures()) != 1 {
		return AccessClaims{}, errors.New("access token must contain exactly one JWS signature")
	}
	headers := message.Signatures()[0].ProtectedHeaders()
	algorithm, ok := headers.Algorithm()
	if !ok || algorithm != jwa.RS256() {
		return AccessClaims{}, errors.New("access token algorithm must be RS256")
	}
	typ, ok := headers.Type()
	if !ok || typ != "JWT" {
		return AccessClaims{}, errors.New("access token typ must be JWT")
	}
	kid, ok := headers.KeyID()
	if !ok || kid == "" {
		return AccessClaims{}, errors.New("access token key ID is required")
	}
	key, ok := v.Keys[kid]
	if !ok {
		return AccessClaims{}, errors.New("access token key ID is not trusted")
	}

	token, err := jwt.Parse(
		[]byte(compact),
		jwt.WithKey(jwa.RS256(), key),
		jwt.WithIssuer(v.Issuer),
		jwt.WithAudience(v.Audience),
		jwt.WithClock(jwt.ClockFunc(v.Now)),
		jwt.WithAcceptableSkew(v.Skew),
		jwt.WithRequiredClaim(jwt.SubjectKey),
		jwt.WithRequiredClaim(jwt.IssuedAtKey),
		jwt.WithRequiredClaim(jwt.ExpirationKey),
	)
	if err != nil {
		return AccessClaims{}, fmt.Errorf("verify access token: %w", err)
	}

	claims := AccessClaims{}
	claims.Subject, _ = token.Subject()
	claims.IssuedAt, _ = token.IssuedAt()
	claims.Expires, _ = token.Expiration()
	if claims.Subject == "" {
		return AccessClaims{}, errors.New("access-token subject is empty")
	}
	if err := readStringClaim(token, "azp", &claims.ClientID); err != nil {
		return AccessClaims{}, err
	}
	_ = readStringClaim(token, "nonce", &claims.Nonce)
	var scope string
	if err := readStringClaim(token, "scope", &scope); err == nil {
		claims.Scopes = strings.Fields(scope)
	}
	return claims, nil
}

// VerifyNonce validates an OIDC ID token and binds it to the initiating login
// attempt. The token signature and registered claims are verified first.
func (v AccessTokenVerifier) VerifyNonce(compact, expected string) (AccessClaims, error) {
	claims, err := v.Verify(compact)
	if err != nil {
		return AccessClaims{}, err
	}
	if expected == "" || claims.Nonce == "" || len(expected) != len(claims.Nonce) {
		return AccessClaims{}, errors.New("OIDC nonce mismatch")
	}
	var difference byte
	for index := range expected {
		difference |= expected[index] ^ claims.Nonce[index]
	}
	if difference != 0 {
		return AccessClaims{}, errors.New("OIDC nonce mismatch")
	}
	return claims, nil
}

func readStringClaim(token jwt.Token, name string, destination *string) error {
	var value any
	if err := token.Get(name, &value); err != nil {
		return fmt.Errorf("missing %s claim", name)
	}
	text, ok := value.(string)
	if !ok || text == "" {
		return fmt.Errorf("%s claim must be a non-empty string", name)
	}
	*destination = text
	return nil
}
