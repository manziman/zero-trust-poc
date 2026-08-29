package tts

import (
	"context"
	"errors"
	"testing"

	"github.com/manziman/custody/internal/identity"
)

type accessVerifierStub struct {
	claims identity.AccessClaims
	err    error
}

func (stub accessVerifierStub) Verify(string) (identity.AccessClaims, error) {
	return stub.claims, stub.err
}

func TestAccessAuthenticatorAllowsOnlyConfiguredWorkloadClients(t *testing.T) {
	t.Parallel()

	authenticator := AccessAuthenticator{
		Verifier: accessVerifierStub{claims: identity.AccessClaims{
			Subject: "service-account-agent-42", ClientID: "agent-42", Scopes: []string{"patient-records.read"},
		}},
		AllowedClients: map[string]bool{"agent-42": true},
	}
	workload, err := authenticator.Authenticate(context.Background(), "signed")
	if err != nil {
		t.Fatal(err)
	}
	if workload.ID != "agent-42" {
		t.Fatalf("workload = %#v", workload)
	}

	authenticator.Verifier = accessVerifierStub{claims: identity.AccessClaims{Subject: "x", ClientID: "unknown"}}
	if _, err := authenticator.Authenticate(context.Background(), "signed"); err == nil {
		t.Fatal("unknown workload client accepted")
	}
}

func TestAccessSubjectValidatorUsesAuthenticatedSubject(t *testing.T) {
	t.Parallel()

	validator := AccessSubjectValidator{Verifier: accessVerifierStub{
		claims: identity.AccessClaims{Subject: "opaque-human-id", ClientID: "custody-cli", Scopes: []string{"patient-records.read"}},
	}, AllowedClients: map[string]bool{"custody-cli": true}}
	subject, err := validator.Validate(context.Background(), "signed")
	if err != nil {
		t.Fatal(err)
	}
	if subject.ID != "opaque-human-id" {
		t.Fatalf("subject = %#v", subject)
	}

	validator.Verifier = accessVerifierStub{err: errors.New("invalid")}
	if _, err := validator.Validate(context.Background(), "bad"); err == nil {
		t.Fatal("invalid subject token accepted")
	}
}

func TestAccessSubjectValidatorLabelsAutomationPrincipal(t *testing.T) {
	t.Parallel()

	validator := AccessSubjectValidator{
		Verifier: accessVerifierStub{claims: identity.AccessClaims{
			Subject: "realm-generated-service-account-id", ClientID: "automation-principal",
		}},
		AllowedClients:          map[string]bool{"automation-principal": true},
		CanonicalClientSubjects: map[string]bool{"automation-principal": true},
	}
	subject, err := validator.Validate(context.Background(), "signed")
	if err != nil {
		t.Fatal(err)
	}
	if subject.ID != "automation-principal" {
		t.Fatalf("automation subject = %q", subject.ID)
	}
}
