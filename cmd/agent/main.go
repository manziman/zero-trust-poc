package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/manziman/custody/internal/agent"
	"github.com/manziman/custody/internal/flowlog"
	"github.com/manziman/custody/internal/keymaterial"
	"github.com/manziman/custody/internal/service"
	"github.com/manziman/custody/internal/txntoken"
	"github.com/manziman/custody/internal/workload"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 {
		service.Main("agent", version)
		return
	}
	handler, err := application()
	if err != nil {
		log.Fatal(err)
	}
	service.MainWithHandler("agent", version, handler)
}

func application() (http.Handler, error) {
	logger := flowlog.New("agent")
	client := &http.Client{Timeout: 8 * time.Second}
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
	tokens := &workload.TokenSource{
		Endpoint: env("CUSTODY_KEYCLOAK_TOKEN_URL", "http://keycloak:8080/realms/custody/protocol/openid-connect/token"),
		ClientID: "agent-42", ClientSecret: os.Getenv("CUSTODY_AGENT_CLIENT_SECRET"),
		Client: client, Now: time.Now,
	}
	return agent.NewHandler(agent.Config{
		Tokens: tokens, Client: client,
		TTSURL:     env("CUSTODY_TTS_URL", "http://tts:8081/token"),
		GatewayURL: env("CUSTODY_GATEWAY_URL", "http://gateway:8082"),
		Verifier: txntoken.Verifier{
			Issuer: "https://tts.custody.internal/transaction", Audience: "custody.local",
			KeyID: "txn-current", PublicKey: publicKey, Now: time.Now, Skew: 5 * time.Second,
		},
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
