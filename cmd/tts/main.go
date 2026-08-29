// Command tts runs the Transaction Token Service with two independent
// Ed25519 issuers: one for draft-11 Transaction Tokens and one for PostgreSQL
// OAuth access tokens.
package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/manziman/custody/internal/chain"
	"github.com/manziman/custody/internal/dbtoken"
	"github.com/manziman/custody/internal/flowlog"
	"github.com/manziman/custody/internal/identity"
	"github.com/manziman/custody/internal/keymaterial"
	"github.com/manziman/custody/internal/service"
	"github.com/manziman/custody/internal/tenancy"
	"github.com/manziman/custody/internal/tts"
	"github.com/manziman/custody/internal/txntoken"
)

var version = "dev"

func main() {
	// Probes and version queries do not need issuer keys or an available IdP.
	if len(os.Args) > 1 {
		service.Main("tts", version)
		return
	}
	handler, err := application()
	if err != nil {
		log.Fatal(err)
	}
	service.MainWithHandler("tts", version, handler)
}

func application() (http.Handler, error) {
	logger := flowlog.New("tts")
	txnKey, err := keymaterial.LoadOrCreate(env("CUSTODY_TXN_KEY_PATH", "/var/lib/custody/keys/transaction.key"))
	if err != nil {
		return nil, err
	}
	databaseKey, err := keymaterial.LoadOrCreate(env("CUSTODY_DB_KEY_PATH", "/var/lib/custody/keys/database.key"))
	if err != nil {
		return nil, err
	}
	if txnKey.Equal(databaseKey) {
		return nil, fmt.Errorf("transaction and database issuers share key material")
	}
	if err := keymaterial.PublishEd25519PublicKey(
		env("CUSTODY_DATABASE_PUBLIC_KEY_PATH", "/var/lib/custody/jwks/db-current.pub"),
		databaseKey.Public().(ed25519.PublicKey),
	); err != nil {
		return nil, fmt.Errorf("publish database issuer public key: %w", err)
	}

	identityVerifier := &identity.RemoteVerifier{
		Issuer:   env("CUSTODY_KEYCLOAK_ISSUER", "http://127.0.0.1:8080/realms/custody"),
		Audience: "custody-tts",
		JWKSURL:  env("CUSTODY_KEYCLOAK_JWKS_URL", "http://keycloak:8080/realms/custody/protocol/openid-connect/certs"),
		Client:   &http.Client{Timeout: 3 * time.Second},
		Now:      time.Now,
		Skew:     5 * time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := identityVerifier.Refresh(ctx); err != nil {
		return nil, fmt.Errorf("load Keycloak JWKS: %w", err)
	}
	go refreshJWKS(identityVerifier)

	txnIssuer := txntoken.Issuer{
		Issuer: "https://tts.custody.internal/transaction", Audience: "custody.local",
		KeyID: "txn-current", PrivateKey: txnKey, TTL: time.Minute, Now: time.Now,
	}
	databaseIssuer := dbtoken.Issuer{
		Issuer: "https://tts.custody.internal/database", Audience: "postgresql://custody",
		KeyID: "db-current", PrivateKey: databaseKey, TTL: 30 * time.Second,
		Now: time.Now, NewTokenID: tts.RandomTransactionID,
	}
	txnJWKS, err := keymaterial.JWKS(txnKey.Public(), txnIssuer.KeyID)
	if err != nil {
		return nil, err
	}
	databaseJWKS, err := keymaterial.JWKS(databaseKey.Public(), databaseIssuer.KeyID)
	if err != nil {
		return nil, err
	}
	databaseReplays := chain.NewReplayCache(time.Now)
	directory := tenancy.DemoDirectory()
	api := tts.NewHandler(tts.Config{
		Workloads: tts.AccessAuthenticator{
			Verifier:       identityVerifier,
			AllowedClients: map[string]bool{"agent-42": true, "gateway": true, "resource": true, "demo-app": true, "automation-principal": true, "external-exporter": true, "demo-org-admin": true, "demo-provider": true, "demo-patient": true},
		},
		Subjects: tts.AccessSubjectValidator{
			Verifier:                identityVerifier,
			AllowedClients:          map[string]bool{"custody-cli": true, "automation-principal": true, "external-exporter": true, "demo-org-admin": true, "demo-provider": true, "demo-patient": true},
			CanonicalClientSubjects: map[string]bool{"automation-principal": true, "external-exporter": true, "demo-org-admin": true, "demo-provider": true, "demo-patient": true},
		},
		Issuer: txnIssuer, NewTransactionID: tts.RandomTransactionID,
		TransactionVerifier: txntoken.Verifier{
			Issuer: txnIssuer.Issuer, Audience: txnIssuer.Audience, KeyID: txnIssuer.KeyID,
			PublicKey: txnKey.Public().(ed25519.PublicKey), Now: time.Now, Skew: 5 * time.Second,
		},
		DatabaseIssuer: databaseIssuer, DatabaseCaller: "resource",
		Authorize: directory.Authorize, DatabaseAccess: directory.DatabaseAccess,
		LogEvent:                  logger.Event,
		AcceptDatabaseTransaction: databaseReplays.Accept,
	})
	return ttsApplication(api, txnJWKS, databaseJWKS), nil
}

func ttsApplication(api http.Handler, transactionJWKS, databaseJWKS []byte) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST /token", api)
	mux.Handle("POST /database-token", api)
	mux.HandleFunc("GET /.well-known/transaction-jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(transactionJWKS)
	})
	mux.HandleFunc("GET /.well-known/database-jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(databaseJWKS)
	})
	return mux
}

func refreshJWKS(verifier *identity.RemoteVerifier) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = verifier.Refresh(ctx) // retain the last-known-good set on failure
		cancel()
	}
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
