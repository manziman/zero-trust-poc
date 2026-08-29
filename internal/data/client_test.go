package data

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

type tokenSourceStub struct{}

func (tokenSourceStub) Token(context.Context) (string, error) { return "resource-workload", nil }

type transportFunc func(*http.Request) (*http.Response, error)

func (fn transportFunc) RoundTrip(request *http.Request) (*http.Response, error) { return fn(request) }

type rowStub struct{ json string }

func (row rowStub) Scan(destinations ...any) error {
	*(destinations[0].(*string)) = row.json
	return nil
}

type connectionStub struct{ closed bool }

func (connection *connectionStub) QueryRow(context.Context, string, ...any) pgx.Row {
	return rowStub{json: `[{"id":101},{"id":102},{"id":103}]`}
}
func (connection *connectionStub) Close(context.Context) error { connection.closed = true; return nil }

func TestReadRecordsUsesResourceBoundTokenAndOAuthOnlyConnection(t *testing.T) {
	t.Parallel()

	httpClient := &http.Client{Transport: transportFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Authorization") != "Bearer resource-workload" || request.Header.Get("Txn-Token") != "txn-compact" {
			t.Fatalf("headers = %#v", request.Header)
		}
		return &http.Response{
			StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(`{"access_token":"database-access","token_type":"Bearer","expires_in":30,"database_user":"custody_patient_records_reader"}`)),
		}, nil
	})}
	connection := &connectionStub{}
	var events []string
	client := Client{
		DatabaseURL:   "postgres://alice@postgres:5432/custody?sslmode=disable",
		TokenEndpoint: "http://tts/database-token", WorkloadTokens: tokenSourceStub{},
		HTTPClient: httpClient,
		Connect: func(ctx context.Context, config *pgx.ConnConfig) (Connection, error) {
			if config.User != "custody_patient_records_reader" {
				t.Fatalf("database user = %q, want custody_patient_records_reader", config.User)
			}
			if config.RequireAuth != "oauth" {
				t.Fatalf("RequireAuth = %q", config.RequireAuth)
			}
			token, err := config.OAuthTokenProvider(ctx)
			if err != nil || token != "database-access" {
				t.Fatalf("OAuth token = %q, err = %v", token, err)
			}
			return connection, nil
		},
		Timeout:  5 * time.Second,
		LogEvent: func(name string, _ ...any) { events = append(events, name) },
	}
	body, err := client.ReadRecords(context.Background(), "txn-compact", "txn-1")
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `[{"id":101},{"id":102},{"id":103}]` || !connection.closed {
		t.Fatalf("body = %s, closed = %v", body, connection.closed)
	}
	wantEvents := []string{"database_token.request.started", "database_token.acquired", "postgres.oauth.connect.started", "postgres.oauth.connected", "postgres.query.completed", "postgres.connection.closed"}
	if strings.Join(events, ",") != strings.Join(wantEvents, ",") {
		t.Fatalf("events = %v, want %v", events, wantEvents)
	}
}
