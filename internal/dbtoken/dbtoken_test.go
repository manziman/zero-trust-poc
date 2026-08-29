package dbtoken_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/manziman/custody/internal/authority"
	"github.com/manziman/custody/internal/dbtoken"
)

func patientReadAccess() dbtoken.Access {
	return dbtoken.Access{
		Action: authority.ActionPatientRecordsRead, DatabaseRole: dbtoken.RolePatientRecordsReader,
		Authority: authority.Context{
			PrincipalKind: authority.KindHuman, AccessProfile: authority.ProfilePatientSelf,
			OrganizationID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", PatientID: "101", Actor: "agent-42",
		},
	}
}

func TestIssueAndVerifyDatabaseToken(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	issuer := dbtoken.Issuer{Issuer: "https://tts.internal/db", Audience: "postgresql://custody", KeyID: "db-2026-08",
		PrivateKey: privateKey, TTL: 30 * time.Second, Now: func() time.Time { return now }, NewTokenID: func() string { return "jti-1" }}
	compact, err := issuer.Issue(dbtoken.IssueRequest{TransactionID: "txn-1", Subject: "human-sub", Workload: "agent-42", Access: patientReadAccess()})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := (dbtoken.Verifier{Issuer: issuer.Issuer, Audience: issuer.Audience, KeyID: issuer.KeyID,
		PublicKey: publicKey, Now: func() time.Time { return now }}).Verify(compact)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "human-sub" || claims.Workload != "agent-42" || claims.TransactionID != "txn-1" ||
		claims.TokenID != "jti-1" || claims.Authority.Actor != "agent-42" || claims.Authority.PatientID != "101" ||
		claims.DatabaseRole != dbtoken.RolePatientRecordsReader {
		t.Fatalf("claims = %#v", claims)
	}
}

func TestDatabaseTokenRejectsMissingWorkload(t *testing.T) {
	t.Parallel()
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	issuer := dbtoken.Issuer{Issuer: "issuer", Audience: "postgres", KeyID: "key", PrivateKey: privateKey,
		TTL: time.Second, Now: time.Now, NewTokenID: func() string { return "jti" }}
	if _, err := issuer.Issue(dbtoken.IssueRequest{TransactionID: "txn", Subject: "sub", Access: patientReadAccess()}); err == nil {
		t.Fatal("database token without workload was issued")
	}
}

func TestDatabaseTokenRejectsCallerSelectedRole(t *testing.T) {
	t.Parallel()
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	issuer := dbtoken.Issuer{Issuer: "issuer", Audience: "postgres", KeyID: "key", PrivateKey: privateKey,
		TTL: time.Second, Now: time.Now, NewTokenID: func() string { return "jti" }}
	access := patientReadAccess()
	access.DatabaseRole = dbtoken.RoleOrgExporter
	if _, err := issuer.Issue(dbtoken.IssueRequest{TransactionID: "txn", Subject: "sub", Workload: "agent-42", Access: access}); err == nil {
		t.Fatal("read action was issued an exporter capability")
	}
}
