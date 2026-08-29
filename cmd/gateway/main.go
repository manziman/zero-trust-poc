// Command gateway is the policy enforcement intermediary. It validates the
// action/resource-bound Transaction Token, applies replay protection, and
// forwards the original compact bytes with an independent workload credential.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/manziman/custody/internal/chain"
	"github.com/manziman/custody/internal/flowlog"
	"github.com/manziman/custody/internal/identity"
	"github.com/manziman/custody/internal/keymaterial"
	"github.com/manziman/custody/internal/service"
	"github.com/manziman/custody/internal/txntoken"
	"github.com/manziman/custody/internal/workload"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 {
		service.Main("gateway", version)
		return
	}
	handler, err := application()
	if err != nil {
		log.Fatal(err)
	}
	service.MainWithHandler("gateway", version, handler)
}

func application() (http.Handler, error) {
	logger := flowlog.New("gateway")
	client := &http.Client{Timeout: 5 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	keys, err := keymaterial.FetchEd25519JWKS(ctx, client, env("CUSTODY_TXN_JWKS_URL", "http://tts:8081/.well-known/transaction-jwks.json"))
	if err != nil {
		return nil, fmt.Errorf("load Transaction Token JWKS: %w", err)
	}
	publicKey, ok := keys["txn-current"]
	if !ok {
		return nil, fmt.Errorf("Transaction Token JWKS has no txn-current key")
	}
	keycloak := &identity.RemoteVerifier{
		Issuer: env("CUSTODY_KEYCLOAK_ISSUER", "http://127.0.0.1:8080/realms/custody"), Audience: "gateway",
		JWKSURL: env("CUSTODY_KEYCLOAK_JWKS_URL", "http://keycloak:8080/realms/custody/protocol/openid-connect/certs"),
		Client:  client, Now: time.Now, Skew: 5 * time.Second,
	}
	if err := keycloak.Refresh(ctx); err != nil {
		return nil, fmt.Errorf("load Keycloak JWKS: %w", err)
	}
	resourceTokens := &workload.TokenSource{
		Endpoint: env("CUSTODY_KEYCLOAK_TOKEN_URL", "http://keycloak:8080/realms/custody/protocol/openid-connect/token"),
		ClientID: "gateway", ClientSecret: os.Getenv("CUSTODY_GATEWAY_CLIENT_SECRET"), Client: client, Now: time.Now,
	}
	return chain.NewGatewayHandler(chain.GatewayConfig{
		Verifier: txntoken.Verifier{
			Issuer: "https://tts.custody.internal/transaction", Audience: "custody.local",
			KeyID: "txn-current", PublicKey: publicKey, Now: time.Now, Skew: 5 * time.Second,
		},
		Replays: chain.NewReplayCache(time.Now),
		AuthenticateAgent: func(_ context.Context, compact string) (string, error) {
			claims, err := keycloak.Verify(compact)
			if err != nil {
				logger.Error("workload.authentication_failed", err, "expected_workload", "agent-42")
				return "", err
			}
			if claims.ClientID != "agent-42" && claims.ClientID != "demo-app" && claims.ClientID != "automation-principal" && claims.ClientID != "external-exporter" {
				logger.Event("workload.rejected", "client_id", claims.ClientID)
				return "", fmt.Errorf("client %q is not an approved transaction origin", claims.ClientID)
			}
			return claims.ClientID, nil
		},
		ResourceURL: env("CUSTODY_RESOURCE_URL", "http://resource:8083"),
		ResourceToken: func() (string, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			return resourceTokens.Token(ctx)
		},
		Client:   client,
		LogError: func(err error) { logger.Error("request.failed", err) },
		LogEvent: logger.Event,
	}), nil
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
