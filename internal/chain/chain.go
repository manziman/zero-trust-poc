// Package chain implements the policy gateway and opaque database-resource
// hop. The gateway validates transaction authority. The resource authenticates
// the gateway but forwards the compact token to TTS without trusting claims;
// PostgreSQL ultimately enforces the operation capability and rows.
package chain

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/manziman/custody/internal/authority"
	"github.com/manziman/custody/internal/txntoken"
)

type TokenVerifier interface {
	Verify(string) (txntoken.Claims, error)
}

// ReplayCache provides receiver-local single-use semantics. Separate gateway
// and resource instances allow the same transaction to cross both receivers.
type ReplayCache struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[string]time.Time
}

func NewReplayCache(now func() time.Time) *ReplayCache {
	return &ReplayCache{now: now, entries: make(map[string]time.Time)}
}

func (c *ReplayCache) accept(transactionID string, expires time.Time) bool {
	if c == nil || c.now == nil || transactionID == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for id, expiry := range c.entries {
		if !expiry.After(now) {
			delete(c.entries, id)
		}
	}
	if _, exists := c.entries[transactionID]; exists {
		return false
	}
	c.entries[transactionID] = expires
	return true
}

// Accept records one receiver-local transaction use until its token expiry.
func (c *ReplayCache) Accept(transactionID string, expires time.Time) bool {
	return c.accept(transactionID, expires)
}

type GatewayConfig struct {
	Verifier           TokenVerifier
	Replays            *ReplayCache
	ExpectedAgentToken string
	AuthenticateAgent  func(context.Context, string) (string, error)
	ResourceURL        string
	ResourceToken      func() (string, error)
	Client             *http.Client
	LogError           func(error)
	LogEvent           func(string, ...any)
}

func NewGatewayHandler(config GatewayConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !supportedRoute(r) {
			writeError(w, http.StatusNotImplemented, "not_implemented")
			return
		}
		authenticatedWorkload, ok := authenticateBearerIdentity(r.Context(), r.Header.Values("Authorization"), config.ExpectedAgentToken, config.AuthenticateAgent)
		if !ok {
			writeError(w, http.StatusUnauthorized, "invalid_workload_credential")
			return
		}
		logEvent(config.LogEvent, "workload.authenticated", "workload", authenticatedWorkload)
		compact, claims, err := validateTransaction(r, config.Verifier)
		if err != nil {
			logError(config.LogError, err)
			writeError(w, http.StatusUnauthorized, "invalid_transaction_token")
			return
		}
		// Bind the authenticated network caller to the workload that requested
		// this authority. Being an approved workload is not sufficient to use a
		// different workload's captured Transaction Token.
		if claims.RequestingWorkload != authenticatedWorkload {
			logEvent(config.LogEvent, "workload.transaction_binding_rejected", "authenticated_workload", authenticatedWorkload, "token_workload", claims.RequestingWorkload, "txn", claims.TransactionID)
			writeError(w, http.StatusForbidden, "workload_binding_mismatch")
			return
		}
		if !routeMatchesClaims(r, claims) {
			writeError(w, http.StatusForbidden, "insufficient_scope")
			return
		}
		if !config.Replays.accept(claims.TransactionID, claims.ExpiresAt) {
			writeError(w, http.StatusConflict, "transaction_replay")
			return
		}
		logEvent(config.LogEvent, "transaction.accepted", "txn", claims.TransactionID, "subject", claims.Subject, "workload", claims.RequestingWorkload, "action", claims.Action)
		if config.ResourceToken == nil || config.Client == nil || config.ResourceURL == "" {
			writeError(w, http.StatusServiceUnavailable, "downstream_unavailable")
			return
		}
		logEvent(config.LogEvent, "resource.request.started", "txn", claims.TransactionID, "route", r.URL.RequestURI())
		workloadToken, err := config.ResourceToken()
		if err != nil || workloadToken == "" {
			writeError(w, http.StatusServiceUnavailable, "workload_token_unavailable")
			return
		}
		downstream, err := http.NewRequestWithContext(r.Context(), r.Method, config.ResourceURL+r.URL.RequestURI(), nil)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "downstream_request_failed")
			return
		}
		downstream.Header.Set("Authorization", "Bearer "+workloadToken)
		// Do not parse, normalize, or reissue the Transaction Token at a normal
		// hop. The compact bytes received above are forwarded verbatim.
		downstream.Header["Txn-Token"] = []string{compact}
		downstream.Header.Set("Custody-Transaction-ID", claims.TransactionID)
		downstream.Header.Set("Custody-Action", claims.Action)
		response, err := config.Client.Do(downstream)
		if err != nil {
			logError(config.LogError, err)
			writeError(w, http.StatusBadGateway, "downstream_request_failed")
			return
		}
		defer response.Body.Close()
		logEvent(config.LogEvent, "resource.request.completed", "txn", claims.TransactionID, "status", response.StatusCode)
		if contentType := response.Header.Get("Content-Type"); contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, response.Body)
	})
}

type ResourceConfig struct {
	ExpectedWorkloadToken string
	AuthenticateWorkload  func(context.Context, string) error
	ReadRecords           func(context.Context, string, string) ([]byte, error)
	ReadAvailability      func(context.Context, string, string) ([]byte, error)
	CreateAppointment     func(context.Context, string, string) ([]byte, error)
	ExportRecords         func(context.Context, string, string) ([]byte, error)
	ObserveToken          func(string)
	LogError              func(error)
	LogEvent              func(string, ...any)
}

func NewResourceHandler(config ResourceConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !supportedRoute(r) {
			writeError(w, http.StatusNotImplemented, "not_implemented")
			return
		}
		if !authenticateBearer(r.Context(), r.Header.Values("Authorization"), config.ExpectedWorkloadToken, config.AuthenticateWorkload) {
			writeError(w, http.StatusUnauthorized, "invalid_workload_credential")
			return
		}
		logEvent(config.LogEvent, "workload.authenticated", "workload", "gateway")
		values := r.Header.Values("Txn-Token")
		transactionID := r.Header.Get("Custody-Transaction-ID")
		action := r.Header.Get("Custody-Action")
		if len(values) != 1 || values[0] == "" || transactionID == "" || action == "" {
			writeError(w, http.StatusUnauthorized, "transaction_context_required")
			return
		}
		compact := values[0]
		logEvent(config.LogEvent, "transaction.forwarded_opaque", "txn", transactionID, "action", action)
		if config.ObserveToken != nil {
			config.ObserveToken(compact)
		}
		logEvent(config.LogEvent, "database.query.started", "txn", transactionID, "action", action)
		var body []byte
		var err error
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/patient-records":
			if action == authority.ActionPatientRecordsExport && config.ExportRecords != nil {
				body, err = config.ExportRecords(r.Context(), compact, transactionID)
			} else if config.ReadRecords != nil {
				body, err = config.ReadRecords(r.Context(), compact, transactionID)
			} else {
				err = errors.New("patient record operation is unavailable")
			}
		case r.Method == http.MethodGet && r.URL.Path == "/schedule/providers/17/availability" && config.ReadAvailability != nil:
			body, err = config.ReadAvailability(r.Context(), compact, transactionID)
		case r.Method == http.MethodPost && r.URL.Path == "/schedule/slots/812/appointments" && config.CreateAppointment != nil:
			body, err = config.CreateAppointment(r.Context(), compact, transactionID)
		default:
			err = errors.New("database operation is unavailable")
		}
		if err != nil {
			logError(config.LogError, err)
			writeError(w, http.StatusBadGateway, "database_query_failed")
			return
		}
		logEvent(config.LogEvent, "database.query.completed", "txn", transactionID, "action", action)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
}

func supportedRoute(r *http.Request) bool {
	return (r.Method == http.MethodGet && r.URL.Path == "/patient-records" && r.URL.Query().Get("ids") == "101,102,103,201") ||
		(r.Method == http.MethodGet && r.URL.Path == "/schedule/providers/17/availability") ||
		(r.Method == http.MethodPost && r.URL.Path == "/schedule/slots/812/appointments")
}

func routeMatchesClaims(r *http.Request, claims txntoken.Claims) bool {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/patient-records":
		return claims.Action == authority.ActionPatientRecordsRead || claims.Action == authority.ActionPatientRecordsExport
	case r.Method == http.MethodGet && r.URL.Path == "/schedule/providers/17/availability":
		return claims.Action == authority.ActionAvailabilityRead && claims.Resource.ProviderID == "17"
	case r.Method == http.MethodPost && r.URL.Path == "/schedule/slots/812/appointments":
		return claims.Action == authority.ActionAppointmentCreate && claims.Resource.ProviderID == "17" && claims.Resource.SlotID == "812"
	default:
		return false
	}
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

func validateTransaction(r *http.Request, verifier TokenVerifier) (string, txntoken.Claims, error) {
	values := r.Header.Values("Txn-Token")
	if len(values) != 1 || values[0] == "" || verifier == nil {
		return "", txntoken.Claims{}, errors.New("exactly one transaction token is required")
	}
	claims, err := verifier.Verify(values[0])
	if err != nil {
		return "", txntoken.Claims{}, err
	}
	return values[0], claims, nil
}

func validBearer(values []string, expected string) bool {
	if len(values) != 1 || expected == "" {
		return false
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(values[0], prefix) {
		return false
	}
	presented := strings.TrimPrefix(values[0], prefix)
	return len(presented) == len(expected) && subtle.ConstantTimeCompare([]byte(presented), []byte(expected)) == 1
}

func authenticateBearer(ctx context.Context, values []string, expected string, authenticate func(context.Context, string) error) bool {
	if authenticate == nil {
		return validBearer(values, expected)
	}
	if len(values) != 1 {
		return false
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(values[0], prefix) || len(values[0]) == len(prefix) {
		return false
	}
	return authenticate(ctx, strings.TrimPrefix(values[0], prefix)) == nil
}

func authenticateBearerIdentity(ctx context.Context, values []string, expected string, authenticate func(context.Context, string) (string, error)) (string, bool) {
	if authenticate == nil {
		if validBearer(values, expected) {
			return "agent-42", true
		}
		return "", false
	}
	if len(values) != 1 {
		return "", false
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(values[0], prefix) || len(values[0]) == len(prefix) {
		return "", false
	}
	identity, err := authenticate(ctx, strings.TrimPrefix(values[0], prefix))
	return identity, err == nil && identity != ""
}

func writeError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}
