// Command resource authenticates the gateway, carries the Transaction Token
// opaquely, and exchanges it only when opening a one-shot OAuth PostgreSQL
// connection. It never selects tenant, access profile, or database role.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/manziman/custody/internal/chain"
	"github.com/manziman/custody/internal/data"
	"github.com/manziman/custody/internal/flowlog"
	"github.com/manziman/custody/internal/identity"
	"github.com/manziman/custody/internal/service"
	"github.com/manziman/custody/internal/workload"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 {
		service.Main("resource", version)
		return
	}
	handler, err := application()
	if err != nil {
		log.Fatal(err)
	}
	service.MainWithHandler("resource", version, handler)
}

func application() (http.Handler, error) {
	logger := flowlog.New("resource")
	httpClient := &http.Client{Timeout: 5 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	keycloak := &identity.RemoteVerifier{
		Issuer: env("CUSTODY_KEYCLOAK_ISSUER", "http://127.0.0.1:8080/realms/custody"), Audience: "resource",
		JWKSURL: env("CUSTODY_KEYCLOAK_JWKS_URL", "http://keycloak:8080/realms/custody/protocol/openid-connect/certs"),
		Client:  httpClient, Now: time.Now, Skew: 5 * time.Second,
	}
	if err := keycloak.Refresh(ctx); err != nil {
		return nil, fmt.Errorf("load Keycloak JWKS: %w", err)
	}
	resourceTokens := &workload.TokenSource{
		Endpoint: env("CUSTODY_KEYCLOAK_TOKEN_URL", "http://keycloak:8080/realms/custody/protocol/openid-connect/token"),
		ClientID: "resource", ClientSecret: os.Getenv("CUSTODY_RESOURCE_CLIENT_SECRET"),
		Client: httpClient, Now: time.Now,
	}
	repository := data.Client{
		DatabaseURL:    env("CUSTODY_DATABASE_URL", "postgres://oauth@postgres:5432/custody?sslmode=disable"),
		TokenEndpoint:  env("CUSTODY_DATABASE_TOKEN_URL", "http://tts:8081/database-token"),
		WorkloadTokens: resourceTokens, HTTPClient: httpClient, Timeout: 8 * time.Second,
		LogEvent: logger.Event,
	}
	return chain.NewResourceHandler(chain.ResourceConfig{
		AuthenticateWorkload: func(_ context.Context, compact string) error {
			claims, err := keycloak.Verify(compact)
			if err != nil {
				logger.Error("workload.authentication_failed", err, "expected_workload", "gateway")
				return err
			}
			if claims.ClientID != "gateway" {
				return fmt.Errorf("client %q is not the gateway", claims.ClientID)
			}
			return nil
		},
		ReadRecords: repository.ReadRecords, ExportRecords: repository.ReadRecords,
		ReadAvailability: repository.ReadAvailability, CreateAppointment: repository.CreateAppointment,
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
