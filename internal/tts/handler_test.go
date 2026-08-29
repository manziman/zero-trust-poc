package tts_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/manziman/custody/internal/authority"
	"github.com/manziman/custody/internal/dbtoken"
	"github.com/manziman/custody/internal/tts"
	"github.com/manziman/custody/internal/txntoken"
)

type workloadAuthenticator struct{}

func (workloadAuthenticator) Authenticate(_ context.Context, token string) (tts.Workload, error) {
	return tts.Workload{ID: "agent-42", Scopes: []string{"patient-records.read"}}, nil
}

type subjectValidator struct{}

func (subjectValidator) Validate(_ context.Context, token string) (tts.Subject, error) {
	return tts.Subject{ID: "keycloak:alice-id", Scopes: []string{"patient-records.read"}}, nil
}

type resourceAuthenticator struct{}

func (resourceAuthenticator) Authenticate(_ context.Context, token string) (tts.Workload, error) {
	return tts.Workload{ID: "resource", Scopes: []string{"database-token.issue"}}, nil
}

func TestTokenEndpointIssuesDraft11ResponseFromVerifiedIdentities(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 5, 15, 0, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	var events []string
	handler := tts.NewHandler(tts.Config{
		Workloads: workloadAuthenticator{},
		Subjects:  subjectValidator{},
		Issuer: txntoken.Issuer{
			Issuer:     "https://tts.custody.local/transaction",
			Audience:   "custody.local",
			KeyID:      "txn-2026-08",
			PrivateKey: privateKey,
			TTL:        time.Minute,
			Now:        func() time.Time { return now },
		},
		NewTransactionID: func() string { return "97053963-771d-49cc-a4e3-20aad399c312" },
		Authorize: func(subject, workload, action string, resource authority.Resource) (authority.Context, error) {
			return authority.Context{PrincipalKind: authority.KindHuman, AccessProfile: authority.ProfilePatientSelf,
				OrganizationID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", PatientID: "101", Actor: workload, Resource: resource}, nil
		},
		LogEvent: func(name string, _ ...any) { events = append(events, name) },
	})

	form := url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"audience":             {"custody.local"},
		"action":               {authority.ActionPatientRecordsRead},
		"resource":             {`{}`},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:txn_token"},
		"subject_token":        {"verified-human-token"},
		"subject_token_type":   {"urn:ietf:params:oauth:token-type:access_token"},
	}
	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Authorization", "Bearer verified-agent-token")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		AccessToken     string `json:"access_token"`
		IssuedTokenType string `json:"issued_token_type"`
		TokenType       string `json:"token_type"`
		ExpiresIn       int    `json:"expires_in"`
		Scope           string `json:"scope"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.TokenType != "N_A" || response.ExpiresIn != 60 {
		t.Fatalf("response = %#v", response)
	}
	if response.IssuedTokenType != "urn:ietf:params:oauth:token-type:txn_token" {
		t.Fatalf("issued_token_type = %q", response.IssuedTokenType)
	}

	claims, err := (txntoken.Verifier{
		Issuer:    "https://tts.custody.local/transaction",
		Audience:  "custody.local",
		KeyID:     "txn-2026-08",
		PublicKey: privateKey.Public().(ed25519.PublicKey),
		Now:       func() time.Time { return now.Add(time.Second) },
	}).Verify(response.AccessToken)
	if err != nil {
		t.Fatalf("verify response token: %v", err)
	}
	if claims.Subject != "keycloak:alice-id" || claims.RequestingWorkload != "agent-42" {
		t.Fatalf("claims = %#v", claims)
	}
	wantEvents := []string{"token_exchange.authorized", "transaction_token.issued"}
	if strings.Join(events, ",") != strings.Join(wantEvents, ",") {
		t.Fatalf("events = %v, want %v", events, wantEvents)
	}
}

func TestDatabaseTokenEndpointIsResourceOnlyAndDerivesClaims(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 5, 15, 0, 0, 0, time.UTC)
	txnPrivateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	dbSeed := make([]byte, ed25519.SeedSize)
	dbSeed[0] = 1
	dbPrivateKey := ed25519.NewKeyFromSeed(dbSeed)
	txnIssuer := txntoken.Issuer{
		Issuer: "https://tts/transaction", Audience: "custody.local", KeyID: "txn-key",
		PrivateKey: txnPrivateKey, TTL: time.Minute, Now: func() time.Time { return now },
	}
	txnCompact, err := txnIssuer.Issue(txntoken.IssueRequest{
		TransactionID: "txn-1", Subject: "human-sub", Workload: "agent-42", Action: authority.ActionPatientRecordsRead,
		Authority: authority.Context{PrincipalKind: authority.KindHuman, AccessProfile: authority.ProfileProviderAssigned,
			OrganizationID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", ProviderID: "17", Actor: "agent-42"},
	})
	if err != nil {
		t.Fatal(err)
	}
	dbIssuer := dbtoken.Issuer{
		Issuer: "https://tts/database", Audience: "postgresql://custody", KeyID: "db-key",
		PrivateKey: dbPrivateKey, TTL: 30 * time.Second, Now: func() time.Time { return now },
		NewTokenID: func() string { return "jti-1" },
	}
	databaseAccepted := false
	handler := tts.NewHandler(tts.Config{
		Workloads: resourceAuthenticator{},
		TransactionVerifier: txntoken.Verifier{
			Issuer: txnIssuer.Issuer, Audience: txnIssuer.Audience, KeyID: txnIssuer.KeyID,
			PublicKey: txnPrivateKey.Public().(ed25519.PublicKey), Now: func() time.Time { return now },
		},
		DatabaseIssuer: dbIssuer,
		DatabaseCaller: "resource",
		DatabaseAccess: func(claims txntoken.Claims) (dbtoken.Access, error) {
			if claims.Subject != "human-sub" || claims.Action != authority.ActionPatientRecordsRead {
				t.Fatalf("authorization input = %#v", claims)
			}
			return dbtoken.Access{
				Authority: authority.Context{PrincipalKind: claims.PrincipalKind, AccessProfile: claims.AccessProfile,
					OrganizationID: claims.OrganizationID, ProviderID: claims.ProviderID, Actor: claims.Actor},
				Action: claims.Action, DatabaseRole: dbtoken.RolePatientRecordsReader,
			}, nil
		},
		AcceptDatabaseTransaction: func(string, time.Time) bool {
			if databaseAccepted {
				return false
			}
			databaseAccepted = true
			return true
		},
	})
	request := httptest.NewRequest(http.MethodPost, "/database-token", nil)
	request.Header.Set("Authorization", "Bearer resource-workload-token")
	request.Header.Set("Txn-Token", txnCompact)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		DatabaseUser string `json:"database_user"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	claims, err := (dbtoken.Verifier{
		Issuer: dbIssuer.Issuer, Audience: dbIssuer.Audience, KeyID: dbIssuer.KeyID,
		PublicKey: dbPrivateKey.Public().(ed25519.PublicKey), Now: func() time.Time { return now },
	}).Verify(response.AccessToken)
	if err != nil {
		t.Fatalf("verify database token: %v", err)
	}
	if response.DatabaseUser != dbtoken.RolePatientRecordsReader || claims.Subject != "human-sub" || claims.Authority.Actor != "agent-42" || claims.TransactionID != "txn-1" ||
		claims.Authority.OrganizationID != "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" || claims.Authority.AccessProfile != authority.ProfileProviderAssigned || claims.DatabaseRole != dbtoken.RolePatientRecordsReader {
		t.Fatalf("database claims = %#v", claims)
	}
	replay := httptest.NewRecorder()
	handler.ServeHTTP(replay, request.Clone(request.Context()))
	if replay.Code != http.StatusConflict {
		t.Fatalf("database issuance replay status = %d, want %d", replay.Code, http.StatusConflict)
	}
}
