package workload_test

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/manziman/custody/internal/workload"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return fn(request) }

func TestTokenSourceUsesClientCredentialsAndCachesUntilExpiry(t *testing.T) {
	t.Parallel()

	requests := 0
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.Method != http.MethodPost {
			t.Fatalf("method = %s", request.Method)
		}
		if err := request.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if request.Form.Get("grant_type") != "client_credentials" {
			t.Fatalf("grant = %q", request.Form.Get("grant_type"))
		}
		clientID, secret, ok := request.BasicAuth()
		if !ok || clientID != "agent-42" || secret != "secret" {
			t.Fatal("client authentication was not HTTP Basic")
		}
		return &http.Response{
			StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(`{"access_token":"workload-token","token_type":"Bearer","expires_in":60}`)),
		}, nil
	})}
	source := workload.TokenSource{
		Endpoint: "http://keycloak/token", ClientID: "agent-42", ClientSecret: "secret",
		Client: client, Now: func() time.Time { return now },
	}
	for range 2 {
		token, err := source.Token(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if token != "workload-token" {
			t.Fatalf("token = %q", token)
		}
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want one cached acquisition", requests)
	}
}
