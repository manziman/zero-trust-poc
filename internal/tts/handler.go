// Package tts exposes the remote Transaction Token issuance profile. It keeps
// workload authentication independent from the subject token exchanged under
// RFC 8693.
package tts

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/manziman/custody/internal/authority"
	"github.com/manziman/custody/internal/dbtoken"
	"github.com/manziman/custody/internal/txntoken"
)

const (
	tokenExchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange"
	txnTokenType       = "urn:ietf:params:oauth:token-type:txn_token"
	accessTokenType    = "urn:ietf:params:oauth:token-type:access_token"
	databaseIssueScope = "database-token.issue"
)

// Workload is an authenticated service or agent identity.
type Workload struct {
	ID     string
	Scopes []string
}

// Subject is the authenticated principal represented by a subject token.
type Subject struct {
	ID     string
	Scopes []string
}

// WorkloadAuthenticator validates the caller's independent bearer credential.
type WorkloadAuthenticator interface {
	Authenticate(context.Context, string) (Workload, error)
}

// SubjectValidator validates the RFC 8693 subject_token.
type SubjectValidator interface {
	Validate(context.Context, string) (Subject, error)
}

// TransactionVerifier validates the dedicated token presented by a resource
// service before any database credential can be minted.
type TransactionVerifier interface {
	Verify(string) (txntoken.Claims, error)
}

// Config contains the complete issuance dependencies.
type Config struct {
	Workloads                 WorkloadAuthenticator
	Subjects                  SubjectValidator
	Issuer                    txntoken.Issuer
	NewTransactionID          func() string
	TransactionVerifier       TransactionVerifier
	DatabaseIssuer            dbtoken.Issuer
	DatabaseCaller            string
	Authorize                 func(subject, workload, action string, resource authority.Resource) (authority.Context, error)
	DatabaseAccess            func(txntoken.Claims) (dbtoken.Access, error)
	LogEvent                  func(string, ...any)
	AcceptDatabaseTransaction func(string, time.Time) bool
}

// NewHandler returns the Phase 1 TTS HTTP contract.
func NewHandler(config Config) http.Handler {
	handler := &handler{config: config}
	mux := http.NewServeMux()
	mux.Handle("POST /token", http.HandlerFunc(handler.issue))
	mux.Handle("POST /database-token", http.HandlerFunc(handler.issueDatabaseToken))
	return mux
}

type handler struct {
	config Config
}

func (h *handler) issue(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "form encoding is required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32*1024)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid form")
		return
	}
	if r.Form.Get("grant_type") != tokenExchangeGrant ||
		r.Form.Get("requested_token_type") != txnTokenType ||
		r.Form.Get("subject_token_type") != accessTokenType {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "unsupported token exchange profile")
		return
	}
	if r.Form.Get("audience") != h.config.Issuer.Audience {
		writeOAuthError(w, http.StatusBadRequest, "invalid_target", "unsupported audience")
		return
	}
	if r.Form.Has("db_role") || r.Form.Has("db_capability") || r.Form.Has("org_id") || r.Form.Has("access_profile") {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "caller-supplied authority fields are forbidden")
		return
	}

	if len(r.Header.Values("Authorization")) != 1 {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "workload authentication failed")
		return
	}
	callerToken, err := bearerToken(r.Header.Get("Authorization"))
	if err != nil || h.config.Workloads == nil {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "workload authentication failed")
		return
	}
	workload, err := h.config.Workloads.Authenticate(r.Context(), callerToken)
	if err != nil || workload.ID == "" {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "workload authentication failed")
		return
	}

	if h.config.Subjects == nil || r.Form.Get("subject_token") == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "subject token is required")
		return
	}
	subject, err := h.config.Subjects.Validate(r.Context(), r.Form.Get("subject_token"))
	if err != nil || subject.ID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "subject token is invalid")
		return
	}

	action := strings.TrimSpace(r.Form.Get("action"))
	if action == "" || !scopeAllowed(action, workload.Scopes) || !scopeAllowed(action, subject.Scopes) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "requested action exceeds credential authority")
		return
	}
	var resource authority.Resource
	if encoded := r.Form.Get("resource"); encoded != "" {
		decoder := json.NewDecoder(strings.NewReader(encoded))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&resource); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "resource is invalid")
			return
		}
	}
	if h.config.Authorize == nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "authorization catalog is unavailable")
		return
	}
	authorization, err := h.config.Authorize(subject.ID, workload.ID, action, resource)
	if err != nil {
		writeOAuthError(w, http.StatusForbidden, "access_denied", "principal is not authorized for action and resource")
		return
	}
	if h.config.NewTransactionID == nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "transaction ID generator is unavailable")
		return
	}
	emit(h.config.LogEvent, "token_exchange.authorized", "workload", workload.ID, "subject", subject.ID, "action", action,
		"principal_kind", authorization.PrincipalKind, "access_profile", authorization.AccessProfile, "org_id", authorization.OrganizationID)

	transactionID := h.config.NewTransactionID()
	compact, err := h.config.Issuer.Issue(txntoken.IssueRequest{
		TransactionID: transactionID,
		Subject:       subject.ID,
		Workload:      workload.ID,
		Action:        action,
		Authority:     authorization,
	})
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "token issuance failed")
		return
	}
	emit(h.config.LogEvent, "transaction_token.issued", "txn", transactionID, "workload", workload.ID, "subject", subject.ID, "actor", authorization.Actor, "action", action, "ttl_seconds", int(h.config.Issuer.TTL.Seconds()))

	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":      compact,
		"issued_token_type": txnTokenType,
		"token_type":        "N_A",
		"expires_in":        int(h.config.Issuer.TTL.Seconds()),
		"scope":             action,
	})
}

func (h *handler) issueDatabaseToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if len(r.Header.Values("Authorization")) != 1 {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "workload authentication failed")
		return
	}
	callerToken, err := bearerToken(r.Header.Get("Authorization"))
	if err != nil || h.config.Workloads == nil {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "workload authentication failed")
		return
	}
	workload, err := h.config.Workloads.Authenticate(r.Context(), callerToken)
	if err != nil || workload.ID == "" {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "workload authentication failed")
		return
	}
	if h.config.DatabaseCaller == "" || workload.ID != h.config.DatabaseCaller || !scopeAllowed(databaseIssueScope, workload.Scopes) {
		writeOAuthError(w, http.StatusForbidden, "unauthorized_client", "database-token endpoint is resource-only")
		return
	}
	values := r.Header.Values("Txn-Token")
	if len(values) != 1 || values[0] == "" || h.config.TransactionVerifier == nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "exactly one transaction token is required")
		return
	}
	claims, err := h.config.TransactionVerifier.Verify(values[0])
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "transaction token is invalid")
		return
	}
	if h.config.DatabaseAccess == nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "database authorization is unavailable")
		return
	}
	access, err := h.config.DatabaseAccess(claims)
	if err != nil {
		writeOAuthError(w, http.StatusForbidden, "access_denied", "subject has no database authorization profile")
		return
	}
	if h.config.AcceptDatabaseTransaction == nil || !h.config.AcceptDatabaseTransaction(claims.TransactionID, claims.ExpiresAt) {
		writeOAuthError(w, http.StatusConflict, "invalid_grant", "transaction token was already used for database issuance")
		return
	}
	emit(h.config.LogEvent, "database_token.authorized", "txn", claims.TransactionID, "caller", workload.ID, "subject", claims.Subject, "actor", claims.Actor,
		"originating_workload", claims.RequestingWorkload, "action", claims.Action, "org_id", access.Authority.OrganizationID,
		"principal_kind", access.Authority.PrincipalKind, "access_profile", access.Authority.AccessProfile, "database_role", access.DatabaseRole)
	compact, err := h.config.DatabaseIssuer.Issue(dbtoken.IssueRequest{
		TransactionID: claims.TransactionID,
		Subject:       claims.Subject,
		Workload:      claims.RequestingWorkload,
		Access:        access,
	})
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "database-token issuance failed")
		return
	}
	emit(h.config.LogEvent, "database_token.issued", "txn", claims.TransactionID, "caller", workload.ID, "database_role", access.DatabaseRole, "ttl_seconds", int(h.config.DatabaseIssuer.TTL.Seconds()))
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":  compact,
		"token_type":    "Bearer",
		"expires_in":    int(h.config.DatabaseIssuer.TTL.Seconds()),
		"database_user": access.DatabaseRole,
	})
}

func emit(logger func(string, ...any), name string, attributes ...any) {
	if logger != nil {
		logger(name, attributes...)
	}
}

func scopeAllowed(requested string, granted []string) bool {
	for scope := range strings.FieldsSeq(requested) {
		if !slices.Contains(granted, scope) {
			return false
		}
	}
	return true
}

func bearerToken(header string) (string, error) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) || len(header) == len(prefix) {
		return "", errors.New("missing bearer token")
	}
	return strings.TrimSpace(strings.TrimPrefix(header, prefix)), nil
}

func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}

// RandomTransactionID returns a cryptographically random 128-bit identifier
// formatted as a UUID. It avoids coupling transaction identity to process
// counters or timestamps.
func RandomTransactionID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		panic("cryptographic randomness unavailable: " + err.Error())
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(value[:])
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}
