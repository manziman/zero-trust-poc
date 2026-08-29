package agent_test

import (
	"context"
	"crypto/ed25519"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/manziman/custody/internal/agent"
	"github.com/manziman/custody/internal/authority"
	"github.com/manziman/custody/internal/txntoken"
)

type tokenSource struct{}

func (tokenSource) Token(context.Context) (string, error) { return "agent-workload", nil }

type transport func(*http.Request) (*http.Response, error)

func (fn transport) RoundTrip(request *http.Request) (*http.Response, error) { return fn(request) }

func TestRunExchangesSubjectAndForwardsExactTransactionToken(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	issuer := txntoken.Issuer{
		Issuer: "issuer", Audience: "custody", KeyID: "key", PrivateKey: privateKey,
		TTL: time.Minute, Now: func() time.Time { return now },
	}
	compact, err := issuer.Issue(txntoken.IssueRequest{
		TransactionID: "txn-1", Subject: "human", Workload: "agent-42", Action: authority.ActionPatientRecordsRead,
		Authority: authority.Context{PrincipalKind: authority.KindHuman, AccessProfile: authority.ProfilePatientSelf,
			OrganizationID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", PatientID: "101", Actor: "agent-42"},
	})
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: transport(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Host {
		case "tts":
			if err := request.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if request.Form.Get("subject_token") != "human-token" || request.Header.Get("Authorization") != "Bearer agent-workload" {
				t.Fatal("TTS did not receive independent subject and workload credentials")
			}
			return response(`{"access_token":"` + compact + `","issued_token_type":"urn:ietf:params:oauth:token-type:txn_token","token_type":"N_A","expires_in":60}`), nil
		case "gateway":
			if request.Header.Get("Txn-Token") != compact || request.Header.Get("Authorization") != "Bearer agent-workload" {
				t.Fatal("gateway headers did not preserve token separation")
			}
			return response(`[{"id":101},{"id":102},{"id":103}]`), nil
		default:
			t.Fatalf("unexpected host %q", request.URL.Host)
			return nil, nil
		}
	})}
	var events []string
	handler := agent.NewHandler(agent.Config{
		Tokens: tokenSource{}, Client: client, TTSURL: "http://tts/token", GatewayURL: "http://gateway",
		Verifier: txntoken.Verifier{
			Issuer: issuer.Issuer, Audience: issuer.Audience, KeyID: issuer.KeyID,
			PublicKey: privateKey.Public().(ed25519.PublicKey), Now: func() time.Time { return now },
		},
		LogEvent: func(name string, _ ...any) { events = append(events, name) },
	})
	request := httptest.NewRequest(http.MethodPost, "/run", nil)
	request.Header.Set("Authorization", "Bearer human-token")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"txn":"txn-1"`) {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	wantEvents := []string{"request.accepted", "workload.authenticated", "transaction.issued", "gateway.request.completed"}
	if strings.Join(events, ",") != strings.Join(wantEvents, ",") {
		t.Fatalf("events = %v, want %v", events, wantEvents)
	}
}

func response(body string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}
