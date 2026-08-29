package identity

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

func TestAccessTokenVerifierDerivesIdentityFromSignedClaims(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	compact := signAccessToken(t, privateKey, now, "custody-tts", "agent-42")
	verifier := AccessTokenVerifier{
		Issuer:   "http://keycloak:8080/realms/custody",
		Audience: "custody-tts",
		Keys:     map[string]any{"keycloak-current": &privateKey.PublicKey},
		Now:      func() time.Time { return now },
	}

	claims, err := verifier.Verify(compact)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if claims.Subject != "11111111-1111-4111-8111-111111111111" {
		t.Fatalf("subject = %q", claims.Subject)
	}
	if claims.ClientID != "agent-42" {
		t.Fatalf("client ID = %q", claims.ClientID)
	}
	if len(claims.Scopes) != 1 || claims.Scopes[0] != "patient-records.read" {
		t.Fatalf("scopes = %#v", claims.Scopes)
	}
	if _, err := verifier.VerifyNonce(compact, "wrong"); err == nil {
		t.Fatal("wrong OIDC nonce accepted")
	}
	if _, err := verifier.VerifyNonce(compact, "nonce-1"); err != nil {
		t.Fatalf("valid OIDC nonce rejected: %v", err)
	}
}

func TestAccessTokenVerifierRejectsWrongAudience(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	compact := signAccessToken(t, privateKey, now, "other-service", "agent-42")
	verifier := AccessTokenVerifier{
		Issuer:   "http://keycloak:8080/realms/custody",
		Audience: "custody-tts",
		Keys:     map[string]any{"keycloak-current": &privateKey.PublicKey},
		Now:      func() time.Time { return now },
	}

	if _, err := verifier.Verify(compact); err == nil {
		t.Fatal("wrong-audience token accepted")
	}
}

func signAccessToken(t *testing.T, key *rsa.PrivateKey, now time.Time, audience, clientID string) string {
	t.Helper()
	token := jwt.New()
	for name, value := range map[string]any{
		jwt.IssuerKey:     "http://keycloak:8080/realms/custody",
		jwt.SubjectKey:    "11111111-1111-4111-8111-111111111111",
		jwt.AudienceKey:   []string{audience},
		jwt.IssuedAtKey:   now,
		jwt.ExpirationKey: now.Add(time.Minute),
		"azp":             clientID,
		"scope":           "patient-records.read",
		"nonce":           "nonce-1",
	} {
		if err := token.Set(name, value); err != nil {
			t.Fatal(err)
		}
	}
	headers := jws.NewHeaders()
	if err := headers.Set(jws.TypeKey, "JWT"); err != nil {
		t.Fatal(err)
	}
	if err := headers.Set(jws.KeyIDKey, "keycloak-current"); err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), key, jws.WithProtectedHeaders(headers)))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}
