package tts

import (
	"context"
	"errors"

	"github.com/manziman/custody/internal/identity"
)

type AccessVerifier interface {
	Verify(string) (identity.AccessClaims, error)
}

// AccessAuthenticator adapts verified Keycloak service-account claims to the
// TTS workload-authentication boundary.
type AccessAuthenticator struct {
	Verifier       AccessVerifier
	AllowedClients map[string]bool
}

func (a AccessAuthenticator) Authenticate(_ context.Context, compact string) (Workload, error) {
	if a.Verifier == nil || len(a.AllowedClients) == 0 {
		return Workload{}, errors.New("workload authenticator is not configured")
	}
	claims, err := a.Verifier.Verify(compact)
	if err != nil {
		return Workload{}, err
	}
	if !a.AllowedClients[claims.ClientID] {
		return Workload{}, errors.New("workload client is not authorized")
	}
	return Workload{ID: claims.ClientID, Scopes: claims.Scopes}, nil
}

// AccessSubjectValidator adapts a separately verified human or explicitly
// labeled automation principal to the token-exchange subject boundary.
type AccessSubjectValidator struct {
	Verifier                AccessVerifier
	AllowedClients          map[string]bool
	CanonicalClientSubjects map[string]bool
}

func (v AccessSubjectValidator) Validate(_ context.Context, compact string) (Subject, error) {
	if v.Verifier == nil || len(v.AllowedClients) == 0 {
		return Subject{}, errors.New("subject validator is not configured")
	}
	claims, err := v.Verifier.Verify(compact)
	if err != nil {
		return Subject{}, err
	}
	if !v.AllowedClients[claims.ClientID] {
		return Subject{}, errors.New("subject client is not authorized")
	}
	if v.CanonicalClientSubjects[claims.ClientID] {
		// CI is explicitly a non-human principal. Keycloak service-account user
		// UUIDs are realm-generated, so the stable client ID is its canonical
		// subject identifier in the headless fixture.
		claims.Subject = claims.ClientID
	}
	return Subject{ID: claims.Subject, Scopes: claims.Scopes}, nil
}
