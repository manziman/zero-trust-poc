// Package health provides the uniform liveness and readiness contract used by
// every Custody service. Keeping this contract deliberately small makes the
// Phase 0 stack observable without implying that business APIs exist yet.
package health

import (
	"encoding/json"
	"net/http"
)

// Response is the stable JSON shape returned by health endpoints.
type Response struct {
	Service string `json:"service"`
	Status  string `json:"status"`
	Version string `json:"version"`
}

// NewHandler constructs liveness and readiness endpoints for a service.
func NewHandler(service, version string) http.Handler {
	mux := http.NewServeMux()
	response := Response{Service: service, Status: "ok", Version: version}
	mux.Handle("GET /health/live", jsonHandler(response))
	mux.Handle("GET /health/ready", jsonHandler(response))
	return mux
}

func jsonHandler(response Response) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, "encode health response", http.StatusInternalServerError)
		}
	}
}
