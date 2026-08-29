package chain_test

import (
	"context"
	"crypto/ed25519"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/manziman/custody/internal/authority"
	"github.com/manziman/custody/internal/chain"
	"github.com/manziman/custody/internal/txntoken"
)

type handlerTransport struct {
	handler http.Handler
}

func (transport handlerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	transport.handler.ServeHTTP(recorder, request)
	return recorder.Result(), nil
}

func TestGatewayForwardsExactTransactionTokenAndRejectsReceiverReplay(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 5, 15, 0, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	issuer := txntoken.Issuer{
		Issuer: "https://tts/transaction", Audience: "custody.local", KeyID: "txn-key",
		PrivateKey: privateKey, TTL: time.Minute, Now: func() time.Time { return now },
	}
	compact, err := issuer.Issue(txntoken.IssueRequest{
		TransactionID: "txn-chain", Subject: "human-sub", Workload: "agent-42", Action: authority.ActionPatientRecordsRead,
		Authority: authority.Context{PrincipalKind: authority.KindHuman, AccessProfile: authority.ProfilePatientSelf,
			OrganizationID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", PatientID: "101", Actor: "agent-42"},
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier := txntoken.Verifier{
		Issuer: issuer.Issuer, Audience: issuer.Audience, KeyID: issuer.KeyID,
		PublicKey: privateKey.Public().(ed25519.PublicKey), Now: func() time.Time { return now },
	}

	var resourceToken string
	var resourceEvents []string
	resource := chain.NewResourceHandler(chain.ResourceConfig{
		ExpectedWorkloadToken: "gateway-workload-token",
		ReadRecords: func(_ context.Context, _, _ string) ([]byte, error) {
			return []byte(`[{"id":101},{"id":102},{"id":103}]`), nil
		},
		ObserveToken: func(value string) { resourceToken = value },
		LogEvent:     func(name string, _ ...any) { resourceEvents = append(resourceEvents, name) },
	})

	var gatewayEvents []string
	gateway := chain.NewGatewayHandler(chain.GatewayConfig{
		Verifier:           verifier,
		Replays:            chain.NewReplayCache(func() time.Time { return now }),
		ExpectedAgentToken: "agent-workload-token",
		ResourceURL:        "http://resource.internal",
		ResourceToken:      func() (string, error) { return "gateway-workload-token", nil },
		Client:             &http.Client{Transport: handlerTransport{handler: resource}},
		LogEvent:           func(name string, _ ...any) { gatewayEvents = append(gatewayEvents, name) },
	})
	request := httptest.NewRequest(http.MethodGet, "/patient-records?ids=101,102,103,201", nil)
	request.Header.Set("Authorization", "Bearer agent-workload-token")
	request.Header.Set("Txn-Token", compact)
	recorder := httptest.NewRecorder()

	gateway.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if resourceToken != compact {
		t.Fatal("resource did not receive byte-identical Transaction Token")
	}
	body, _ := io.ReadAll(recorder.Body)
	if string(body) != `[{"id":101},{"id":102},{"id":103}]` {
		t.Fatalf("body = %s", body)
	}
	assertEvents(t, gatewayEvents, []string{"workload.authenticated", "transaction.accepted", "resource.request.started", "resource.request.completed"})
	assertEvents(t, resourceEvents, []string{"workload.authenticated", "transaction.forwarded_opaque", "database.query.started", "database.query.completed"})

	replay := httptest.NewRecorder()
	gateway.ServeHTTP(replay, request.Clone(request.Context()))
	if replay.Code != http.StatusConflict {
		t.Fatalf("replay status = %d, want %d", replay.Code, http.StatusConflict)
	}
}

func TestAvailabilityTokenCannotCreateAppointment(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 5, 15, 0, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	issuer := txntoken.Issuer{Issuer: "issuer", Audience: "audience", KeyID: "key", PrivateKey: privateKey, TTL: time.Minute, Now: func() time.Time { return now }}
	compact, err := issuer.Issue(txntoken.IssueRequest{
		TransactionID: "txn-substitution", Subject: "demo-patient", Workload: "agent-42", Action: authority.ActionAvailabilityRead,
		Authority: authority.Context{PrincipalKind: authority.KindHuman, AccessProfile: authority.ProfilePatientSelf,
			OrganizationID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", PatientID: "101", Actor: "agent-42", Resource: authority.Resource{ProviderID: "17"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	gateway := chain.NewGatewayHandler(chain.GatewayConfig{
		Verifier: txntoken.Verifier{Issuer: issuer.Issuer, Audience: issuer.Audience, KeyID: issuer.KeyID, PublicKey: privateKey.Public().(ed25519.PublicKey), Now: func() time.Time { return now }},
		Replays:  chain.NewReplayCache(func() time.Time { return now }), ExpectedAgentToken: "agent-token",
	})
	request := httptest.NewRequest(http.MethodPost, "/schedule/slots/812/appointments", nil)
	request.Header.Set("Authorization", "Bearer agent-token")
	request.Header.Set("Txn-Token", compact)
	recorder := httptest.NewRecorder()
	gateway.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", recorder.Code)
	}
}

func TestGatewayBindsTransactionToAuthenticatedWorkload(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 5, 15, 0, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	issuer := txntoken.Issuer{Issuer: "issuer", Audience: "audience", KeyID: "key", PrivateKey: privateKey, TTL: time.Minute, Now: func() time.Time { return now }}
	compact, err := issuer.Issue(txntoken.IssueRequest{
		TransactionID: "txn-workload-binding", Subject: "demo-patient", Workload: "agent-42", Action: authority.ActionPatientRecordsRead,
		Authority: authority.Context{PrincipalKind: authority.KindHuman, AccessProfile: authority.ProfilePatientSelf,
			OrganizationID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", PatientID: "101", Actor: "agent-42"},
	})
	if err != nil {
		t.Fatal(err)
	}
	gateway := chain.NewGatewayHandler(chain.GatewayConfig{
		Verifier: txntoken.Verifier{Issuer: issuer.Issuer, Audience: issuer.Audience, KeyID: issuer.KeyID, PublicKey: privateKey.Public().(ed25519.PublicKey), Now: func() time.Time { return now }},
		Replays:  chain.NewReplayCache(func() time.Time { return now }),
		AuthenticateAgent: func(context.Context, string) (string, error) {
			return "demo-app", nil
		},
	})
	request := httptest.NewRequest(http.MethodGet, "/patient-records?ids=101,102,103,201", nil)
	request.Header.Set("Authorization", "Bearer demo-app-token")
	request.Header.Set("Txn-Token", compact)
	recorder := httptest.NewRecorder()
	gateway.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", recorder.Code, recorder.Body.String())
	}
}

func assertEvents(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("events = %v, want %v", got, want)
		}
	}
}
