// Package data owns the resource service's one-shot, per-transaction
// PostgreSQL OAuth connection. It deliberately does not expose a pool.
package data

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/manziman/custody/internal/dbtoken"
)

type WorkloadTokenSource interface {
	Token(context.Context) (string, error)
}

type Connection interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Close(context.Context) error
}

type Client struct {
	DatabaseURL    string
	TokenEndpoint  string
	WorkloadTokens WorkloadTokenSource
	HTTPClient     *http.Client
	Connect        func(context.Context, *pgx.ConnConfig) (Connection, error)
	Timeout        time.Duration
	LogEvent       func(string, ...any)
}

func (c Client) ReadRecords(parent context.Context, transactionToken, transactionID string) ([]byte, error) {
	return c.queryJSON(parent, transactionToken, transactionID, "patient records", `
SELECT COALESCE(
  jsonb_agg(
    jsonb_build_object('id', id, 'organization_id', organization_id, 'patient_name', patient_name, 'diagnosis', diagnosis)
    ORDER BY id
  ),
  '[]'::jsonb
)::text
FROM patient_records
WHERE id = ANY($1::integer[])`, []int32{101, 102, 103, 201})
}

// ReadAvailability queries only the safe bookable-slot relation. The private
// provider calendar is not granted to the capability role at all.
func (c Client) ReadAvailability(parent context.Context, transactionToken, transactionID string) ([]byte, error) {
	return c.queryJSON(parent, transactionToken, transactionID, "provider availability", `
SELECT COALESCE(
  jsonb_agg(jsonb_build_object('slot_id', id, 'provider_id', provider_id, 'starts_at', starts_at) ORDER BY starts_at),
  '[]'::jsonb
)::text
FROM provider_bookable_slots`, nil)
}

// CreateAppointment calls a narrow database function. Organization, patient,
// provider, transaction, and creator fields come from signed OAuth context;
// the workload cannot provide or override them.
func (c Client) CreateAppointment(parent context.Context, transactionToken, transactionID string) ([]byte, error) {
	return c.queryJSON(parent, transactionToken, transactionID, "appointment creation", `
SELECT jsonb_build_object(
  'appointment_id', appointment_id,
  'patient_id', patient_id,
  'provider_id', provider_id,
  'slot_id', slot_id,
  'status', status
)::text
FROM custody_context.create_appointment()`, nil)
}

func (c Client) queryJSON(parent context.Context, transactionToken, transactionID, operation, query string, argument any) ([]byte, error) {
	if c.DatabaseURL == "" || c.TokenEndpoint == "" || c.WorkloadTokens == nil || c.HTTPClient == nil || transactionToken == "" || transactionID == "" || c.Timeout <= 0 {
		return nil, errors.New("data client configuration or transaction identity is incomplete")
	}
	ctx, cancel := context.WithTimeout(parent, c.Timeout)
	defer cancel()
	emit(c.LogEvent, "database_token.request.started", "txn", transactionID, "caller", "resource")
	databaseCredential, err := c.databaseToken(ctx, transactionToken)
	if err != nil {
		return nil, err
	}
	emit(c.LogEvent, "database_token.acquired", "txn", transactionID, "ttl_max_seconds", 30)
	config, err := pgx.ParseConfig(c.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database URL: %w", err)
	}
	config.User = databaseCredential.User
	config.RequireAuth = "oauth"
	config.RuntimeParams["application_name"] = "custody txn=" + transactionID
	config.OAuthTokenProvider = func(providerContext context.Context) (string, error) {
		if err := providerContext.Err(); err != nil {
			return "", err
		}
		return databaseCredential.Token, nil
	}
	connect := c.Connect
	if connect == nil {
		connect = func(ctx context.Context, config *pgx.ConnConfig) (Connection, error) {
			return pgx.ConnectConfig(ctx, config)
		}
	}
	emit(c.LogEvent, "postgres.oauth.connect.started", "txn", transactionID, "database_user", config.User, "required_auth", config.RequireAuth)
	connection, err := connect(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("connect with database OAuth token: %w", err)
	}
	emit(c.LogEvent, "postgres.oauth.connected", "txn", transactionID, "database_user", config.User)
	defer func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer closeCancel()
		_ = connection.Close(closeCtx)
		emit(c.LogEvent, "postgres.connection.closed", "txn", transactionID)
	}()

	var document string
	var row pgx.Row
	if argument == nil {
		row = connection.QueryRow(ctx, query)
	} else {
		row = connection.QueryRow(ctx, query, argument)
	}
	if err := row.Scan(&document); err != nil {
		return nil, fmt.Errorf("database %s: %w", operation, err)
	}
	if !json.Valid([]byte(document)) {
		return nil, errors.New("database returned invalid JSON")
	}
	emit(c.LogEvent, "postgres.query.completed", "txn", transactionID, "command", "SELECT", "operation", operation)
	return []byte(document), nil
}

func emit(logger func(string, ...any), name string, attributes ...any) {
	if logger != nil {
		logger(name, attributes...)
	}
}

type databaseCredential struct {
	Token string
	User  string
}

func (c Client) databaseToken(ctx context.Context, transactionToken string) (databaseCredential, error) {
	workloadToken, err := c.WorkloadTokens.Token(ctx)
	if err != nil {
		return databaseCredential{}, fmt.Errorf("acquire resource workload token: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenEndpoint, nil)
	if err != nil {
		return databaseCredential{}, err
	}
	request.Header.Set("Authorization", "Bearer "+workloadToken)
	request.Header["Txn-Token"] = []string{transactionToken}
	response, err := c.HTTPClient.Do(request)
	if err != nil {
		return databaseCredential{}, fmt.Errorf("request database token: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if err != nil {
		return databaseCredential{}, err
	}
	if len(body) > 64*1024 {
		return databaseCredential{}, errors.New("database-token response is too large")
	}
	if response.StatusCode != http.StatusOK {
		return databaseCredential{}, fmt.Errorf("database-token endpoint returned %s", response.Status)
	}
	var result struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		DatabaseUser string `json:"database_user"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return databaseCredential{}, fmt.Errorf("decode database token: %w", err)
	}
	if result.AccessToken == "" || result.TokenType != "Bearer" || result.ExpiresIn <= 0 || result.ExpiresIn > 30 ||
		(result.DatabaseUser != dbtoken.RolePatientRecordsReader && result.DatabaseUser != dbtoken.RoleAvailabilityReader &&
			result.DatabaseUser != dbtoken.RoleAppointmentCreator && result.DatabaseUser != dbtoken.RoleOrgExporter && result.DatabaseUser != dbtoken.RolePatientImporter) {
		return databaseCredential{}, errors.New("database-token response violates the local profile")
	}
	return databaseCredential{Token: result.AccessToken, User: result.DatabaseUser}, nil
}
