// Command postgres-oauth-smoke proves the Phase 0 PostgreSQL 18 OAUTHBEARER
// boundary. It injects a pre-existing token through pgx, then reports the
// authenticated OAuth identity and active database role separately.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const defaultDatabaseURL = "postgres://custody_org_admin@postgres:5432/custody?sslmode=disable"

type result struct {
	SystemUser  string `json:"system_user"`
	CurrentUser string `json:"current_user"`
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	token := os.Getenv("CUSTODY_OAUTH_TOKEN")
	if token == "" {
		return errors.New("CUSTODY_OAUTH_TOKEN is required")
	}
	config, err := databaseConfig(
		envOrDefault("CUSTODY_OAUTH_DATABASE_URL", defaultDatabaseURL),
		token,
	)
	if err != nil {
		return err
	}

	connection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return fmt.Errorf("oauth connection: %w", err)
	}
	defer connection.Close(context.Background())

	var identity result
	if err := connection.QueryRow(ctx, "SELECT system_user, current_user").Scan(
		&identity.SystemUser,
		&identity.CurrentUser,
	); err != nil {
		return fmt.Errorf("query identity: %w", err)
	}
	if !strings.HasPrefix(identity.SystemUser, "oauth:v1:") {
		return fmt.Errorf("system_user = %q, want structured OAuth identity", identity.SystemUser)
	}
	if identity.CurrentUser != config.User {
		return fmt.Errorf("current_user = %q, want %q", identity.CurrentUser, config.User)
	}

	if err := json.NewEncoder(os.Stdout).Encode(identity); err != nil {
		return fmt.Errorf("encode result: %w", err)
	}
	return nil
}

func databaseConfig(databaseURL, token string) (*pgx.ConnConfig, error) {
	config, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database config: %w", err)
	}
	config.RequireAuth = "oauth"
	config.OAuthTokenProvider = func(providerCtx context.Context) (string, error) {
		if err := providerCtx.Err(); err != nil {
			return "", err
		}
		return token, nil
	}
	return config, nil
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
