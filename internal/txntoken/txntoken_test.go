package txntoken_test

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/manziman/custody/internal/authority"
	"github.com/manziman/custody/internal/txntoken"
)

func TestIssuedTokenCarriesTheDraft11IdentityContract(t *testing.T) {
	t.Parallel()

	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	now := time.Date(2026, 8, 5, 15, 0, 0, 0, time.UTC)
	issuer := txntoken.Issuer{
		Issuer:     "https://tts.custody.local/transaction",
		Audience:   "custody.local",
		KeyID:      "txn-2026-08",
		PrivateKey: privateKey,
		TTL:        time.Minute,
		Now:        func() time.Time { return now },
	}

	compact, err := issuer.Issue(txntoken.IssueRequest{
		TransactionID: "97053963-771d-49cc-a4e3-20aad399c312",
		Subject:       "keycloak:alice-id",
		Workload:      "agent-42",
		Action:        authority.ActionPatientRecordsRead,
		Authority: authority.Context{
			PrincipalKind: authority.KindHuman, AccessProfile: authority.ProfilePatientSelf,
			OrganizationID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", PatientID: "101",
		},
		TransactionContext: map[string]any{
			"action": "READ",
		},
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	claims, err := (txntoken.Verifier{
		Issuer:    "https://tts.custody.local/transaction",
		Audience:  "custody.local",
		PublicKey: privateKey.Public().(ed25519.PublicKey),
		KeyID:     "txn-2026-08",
		Now:       func() time.Time { return now.Add(30 * time.Second) },
	}).Verify(compact)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if claims.TransactionID != "97053963-771d-49cc-a4e3-20aad399c312" {
		t.Fatalf("txn = %q", claims.TransactionID)
	}
	if claims.Subject != "keycloak:alice-id" {
		t.Fatalf("sub = %q", claims.Subject)
	}
	if claims.RequestingWorkload != "agent-42" {
		t.Fatalf("req_wl = %q", claims.RequestingWorkload)
	}
	if claims.Action != authority.ActionPatientRecordsRead || claims.PrincipalKind != authority.KindHuman || claims.PatientID != "101" {
		t.Fatalf("claims = %#v", claims)
	}
	if got := claims.TransactionContext["action"]; got != "READ" {
		t.Fatalf("tctx.action = %#v", got)
	}
}
