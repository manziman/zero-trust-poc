package health_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/manziman/custody/internal/health"
)

func TestEndpoints(t *testing.T) {
	t.Parallel()

	for _, path := range []string{"/health/live", "/health/ready"} {
		path := path
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			request := httptest.NewRequest(http.MethodGet, path, nil)
			response := httptest.NewRecorder()
			health.NewHandler("tts", "test").ServeHTTP(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
			}

			var body health.Response
			if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if body.Service != "tts" || body.Status != "ok" || body.Version != "test" {
				t.Fatalf("unexpected body: %#v", body)
			}
		})
	}
}

func TestUnknownRouteIsNotFound(t *testing.T) {
	t.Parallel()

	response := httptest.NewRecorder()
	health.NewHandler("gateway", "test").ServeHTTP(
		response,
		httptest.NewRequest(http.MethodGet, "/", nil),
	)

	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
}
