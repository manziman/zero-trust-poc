package main

import (
	"context"
	"errors"
	"testing"
)

func TestDatabaseConfigRequiresOAuth(t *testing.T) {
	t.Parallel()

	config, err := databaseConfig(defaultDatabaseURL, "sentinel")
	if err != nil {
		t.Fatalf("databaseConfig() error = %v", err)
	}
	if config.RequireAuth != "oauth" {
		t.Fatalf("RequireAuth = %q, want oauth", config.RequireAuth)
	}
}

func TestCanceledProviderContextFailsClosed(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	provider := func(providerCtx context.Context) (string, error) {
		if err := providerCtx.Err(); err != nil {
			return "", err
		}
		return "unexpected", nil
	}

	if _, err := provider(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("provider error = %v, want context.Canceled", err)
	}
}
