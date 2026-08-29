// Package service owns the common process lifecycle for Custody's small HTTP
// services: configuration, structured logs, bounded timeouts, health probing,
// signal handling, and graceful shutdown.
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/manziman/custody/internal/health"
)

const (
	defaultAddress        = ":8080"
	defaultShutdownWindow = 5 * time.Second
	defaultProbeTimeout   = 2 * time.Second
)

// Config contains the complete Phase 0 runtime contract for a service.
type Config struct {
	Name    string
	Address string
	Version string
	Handler http.Handler
}

// Main implements the process entry point shared by the TTS, gateway, and
// resource-service commands.
func Main(name, version string) {
	MainWithHandler(name, version, nil)
}

// MainWithHandler runs an application handler alongside the uniform health
// contract while retaining the shared process lifecycle.
func MainWithHandler(name, version string, application http.Handler) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("service", name)

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "healthcheck":
			if err := runHealthcheck(); err != nil {
				logger.Error("healthcheck failed", "error", err)
				os.Exit(1)
			}
			return
		case "version":
			fmt.Println(version)
			return
		default:
			logger.Error("unknown command", "command", os.Args[1])
			os.Exit(2)
		}
	}

	config := Config{
		Name:    name,
		Address: envOrDefault("CUSTODY_LISTEN_ADDR", defaultAddress),
		Version: version,
		Handler: application,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := Run(ctx, config, logger); err != nil {
		logger.Error("service stopped", "error", err)
		os.Exit(1)
	}
}

// Run serves until the context is canceled or the HTTP server fails.
func Run(ctx context.Context, config Config, logger *slog.Logger) error {
	if strings.TrimSpace(config.Name) == "" {
		return errors.New("service name is required")
	}
	if strings.TrimSpace(config.Address) == "" {
		return errors.New("listen address is required")
	}

	handler := config.Handler
	if handler == nil {
		handler = health.NewHandler(config.Name, config.Version)
	} else {
		handler = WithHealth(config.Name, config.Version, handler)
	}
	server := &http.Server{
		Addr:              config.Address,
		Handler:           handler,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("service listening", "address", config.Address, "version", config.Version)
		serverErrors <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), defaultShutdownWindow)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		return nil
	case err := <-serverErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve: %w", err)
	}
}

// WithHealth mounts application routes and reserves /health/ for the common
// semantic probe contract.
func WithHealth(name, version string, application http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/health/", health.NewHandler(name, version))
	mux.Handle("/", application)
	return mux
}

// Healthcheck verifies a semantic readiness endpoint rather than only a TCP
// listener. It is exported so the smoke tests and container probe share logic.
func Healthcheck(ctx context.Context, endpoint string) error {
	return healthcheck(ctx, endpoint, http.DefaultClient)
}

func healthcheck(ctx context.Context, endpoint string, client *http.Client) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("request readiness: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("readiness returned %s", response.Status)
	}
	return nil
}

func runHealthcheck() error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultProbeTimeout)
	defer cancel()
	return Healthcheck(ctx, envOrDefault("CUSTODY_HEALTH_URL", "http://127.0.0.1:8080/health/ready"))
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
