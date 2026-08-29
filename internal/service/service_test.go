package service

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthcheck(t *testing.T) {
	t.Parallel()

	client := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusOK), nil
	})}

	if err := healthcheck(context.Background(), "http://service/health/ready", client); err != nil {
		t.Fatalf("Healthcheck() error = %v", err)
	}
}

func TestWithHealthCombinesApplicationAndProbeRoutes(t *testing.T) {
	t.Parallel()

	application := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := WithHealth("tts", "test", application)
	for path, expected := range map[string]int{
		"/token":        http.StatusNoContent,
		"/health/ready": http.StatusOK,
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != expected {
			t.Fatalf("%s status = %d, want %d", path, recorder.Code, expected)
		}
	}
}

func TestHealthcheckRejectsUnhealthyResponse(t *testing.T) {
	t.Parallel()

	client := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusServiceUnavailable), nil
	})}

	if err := healthcheck(context.Background(), "http://service/health/ready", client); err == nil {
		t.Fatal("Healthcheck() error = nil, want failure")
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (fn roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func response(status int) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Body:       io.NopCloser(strings.NewReader("")),
		Header:     make(http.Header),
	}
}
