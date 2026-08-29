// Package agent implements the deterministic non-LLM reference workload used
// to demonstrate separate human and workload identity.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/manziman/custody/internal/authority"
	"github.com/manziman/custody/internal/txntoken"
)

type TokenSource interface {
	Token(context.Context) (string, error)
}

type TokenVerifier interface {
	Verify(string) (txntoken.Claims, error)
}

type Config struct {
	Tokens     TokenSource
	Client     *http.Client
	TTSURL     string
	GatewayURL string
	Verifier   TokenVerifier
	LogError   func(error)
	LogEvent   func(string, ...any)
}

func NewHandler(config Config) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /run", func(w http.ResponseWriter, r *http.Request) {
		run(w, r, config)
	})
	mux.HandleFunc("POST /schedule", func(w http.ResponseWriter, r *http.Request) {
		schedule(w, r, config)
	})
	return mux
}

func run(w http.ResponseWriter, r *http.Request, config Config) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") || len(values[0]) == len("Bearer ") {
		writeError(w, http.StatusUnauthorized, "human_subject_token_required")
		return
	}
	if config.Tokens == nil || config.Client == nil || config.Verifier == nil || config.TTSURL == "" || config.GatewayURL == "" {
		writeError(w, http.StatusServiceUnavailable, "agent_not_ready")
		return
	}
	subjectToken := strings.TrimPrefix(values[0], "Bearer ")
	logEvent(config.LogEvent, "request.accepted", "route", "POST /run")
	workloadToken, err := config.Tokens.Token(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, "workload_token_failed")
		return
	}
	logEvent(config.LogEvent, "workload.authenticated", "workload", "agent-42")
	transactionToken, err := exchange(r.Context(), config, workloadToken, subjectToken, authority.ActionPatientRecordsRead, authority.Resource{})
	if err != nil {
		logError(config.LogError, err)
		writeError(w, http.StatusBadGateway, "transaction_exchange_failed")
		return
	}
	claims, err := config.Verifier.Verify(transactionToken)
	if err != nil {
		logError(config.LogError, err)
		writeError(w, http.StatusBadGateway, "invalid_issued_transaction_token")
		return
	}
	logEvent(config.LogEvent, "transaction.issued", "txn", claims.TransactionID, "subject", claims.Subject, "action", claims.Action)
	records, err := invokeGateway(r.Context(), config, workloadToken, transactionToken, http.MethodGet, "/patient-records?ids=101,102,103,201")
	if err != nil {
		logError(config.LogError, err)
		writeError(w, http.StatusBadGateway, "gateway_request_failed")
		return
	}
	var recordList []json.RawMessage
	if err := json.Unmarshal(records, &recordList); err != nil {
		logError(config.LogError, err)
		writeError(w, http.StatusBadGateway, "gateway_response_invalid")
		return
	}
	logEvent(config.LogEvent, "gateway.request.completed", "txn", claims.TransactionID, "record_count", len(recordList))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		TransactionID string          `json:"txn"`
		Records       json.RawMessage `json:"records"`
	}{TransactionID: claims.TransactionID, Records: records})
}

func schedule(w http.ResponseWriter, r *http.Request, config Config) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") || len(values[0]) == len("Bearer ") {
		writeError(w, http.StatusUnauthorized, "human_subject_token_required")
		return
	}
	if config.Tokens == nil || config.Client == nil || config.Verifier == nil || config.TTSURL == "" || config.GatewayURL == "" {
		writeError(w, http.StatusServiceUnavailable, "agent_not_ready")
		return
	}
	subjectToken := strings.TrimPrefix(values[0], "Bearer ")
	workloadToken, err := config.Tokens.Token(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, "workload_token_failed")
		return
	}
	availabilityResource := authority.Resource{ProviderID: "17"}
	availabilityToken, err := exchange(r.Context(), config, workloadToken, subjectToken, authority.ActionAvailabilityRead, availabilityResource)
	if err != nil {
		logError(config.LogError, err)
		writeError(w, http.StatusBadGateway, "availability_exchange_failed")
		return
	}
	availabilityClaims, err := recordTransaction(r.Context(), config, availabilityToken)
	if err != nil {
		writeError(w, http.StatusBadGateway, "availability_transaction_invalid")
		return
	}
	availability, err := invokeGateway(r.Context(), config, workloadToken, availabilityToken, http.MethodGet, "/schedule/providers/17/availability")
	if err != nil {
		logError(config.LogError, err)
		writeError(w, http.StatusBadGateway, "availability_request_failed")
		return
	}
	appointmentResource := authority.Resource{ProviderID: "17", SlotID: "812"}
	appointmentToken, err := exchange(r.Context(), config, workloadToken, subjectToken, authority.ActionAppointmentCreate, appointmentResource)
	if err != nil {
		logError(config.LogError, err)
		writeError(w, http.StatusBadGateway, "appointment_exchange_failed")
		return
	}
	appointmentClaims, err := recordTransaction(r.Context(), config, appointmentToken)
	if err != nil {
		writeError(w, http.StatusBadGateway, "appointment_transaction_invalid")
		return
	}
	appointment, err := invokeGateway(r.Context(), config, workloadToken, appointmentToken, http.MethodPost, "/schedule/slots/812/appointments")
	if err != nil {
		logError(config.LogError, err)
		writeError(w, http.StatusBadGateway, "appointment_request_failed")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		AvailabilityTransaction string          `json:"availability_txn"`
		AppointmentTransaction  string          `json:"appointment_txn"`
		Availability            json.RawMessage `json:"availability"`
		Appointment             json.RawMessage `json:"appointment"`
	}{availabilityClaims.TransactionID, appointmentClaims.TransactionID, availability, appointment})
}

func recordTransaction(_ context.Context, config Config, compact string) (txntoken.Claims, error) {
	claims, err := config.Verifier.Verify(compact)
	if err != nil {
		logError(config.LogError, err)
		return txntoken.Claims{}, err
	}
	logEvent(config.LogEvent, "transaction.issued", "txn", claims.TransactionID, "subject", claims.Subject, "actor", claims.Actor, "action", claims.Action)
	return claims, nil
}

func logEvent(logger func(string, ...any), name string, attributes ...any) {
	if logger != nil {
		logger(name, attributes...)
	}
}

func logError(logger func(error), err error) {
	if logger != nil {
		logger(err)
	}
}

func exchange(ctx context.Context, config Config, workloadToken, subjectToken, action string, resource authority.Resource) (string, error) {
	encodedResource, err := json.Marshal(resource)
	if err != nil {
		return "", err
	}
	form := url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"audience":             {"custody.local"},
		"action":               {action},
		"resource":             {string(encodedResource)},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:txn_token"},
		"subject_token":        {subjectToken},
		"subject_token_type":   {"urn:ietf:params:oauth:token-type:access_token"},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, config.TTSURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Authorization", "Bearer "+workloadToken)
	response, err := config.Client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, err := readBounded(response)
	if err != nil {
		return "", err
	}
	var result struct {
		AccessToken     string `json:"access_token"`
		IssuedTokenType string `json:"issued_token_type"`
		TokenType       string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	if result.AccessToken == "" || result.IssuedTokenType != "urn:ietf:params:oauth:token-type:txn_token" || result.TokenType != "N_A" {
		return "", errors.New("TTS response violates transaction-token profile")
	}
	return result.AccessToken, nil
}

func invokeGateway(ctx context.Context, config Config, workloadToken, transactionToken, method, path string) (json.RawMessage, error) {
	request, err := http.NewRequestWithContext(ctx, method, config.GatewayURL+path, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+workloadToken)
	request.Header["Txn-Token"] = []string{transactionToken}
	response, err := config.Client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := readBounded(response)
	if err != nil {
		return nil, err
	}
	if !json.Valid(body) {
		return nil, errors.New("gateway returned invalid JSON")
	}
	return body, nil
}

func readBounded(response *http.Response) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024+1))
	if err != nil {
		return nil, err
	}
	if len(body) > 1024*1024 {
		return nil, errors.New("response is too large")
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream returned %s", response.Status)
	}
	return body, nil
}

func writeError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}
