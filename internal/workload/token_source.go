// Package workload obtains and caches independently authenticated Keycloak
// service-account credentials for internal service-to-service calls.
package workload

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type TokenSource struct {
	Endpoint     string
	ClientID     string
	ClientSecret string
	Scope        string
	Client       *http.Client
	Now          func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time
}

func (s *TokenSource) Token(ctx context.Context) (string, error) {
	if s == nil || s.Endpoint == "" || s.ClientID == "" || s.ClientSecret == "" || s.Client == nil || s.Now == nil {
		return "", errors.New("workload token source configuration is incomplete")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != "" && s.expires.After(s.Now().Add(5*time.Second)) {
		return s.token, nil
	}
	form := url.Values{"grant_type": {"client_credentials"}}
	if s.Scope != "" {
		form.Set("scope", s.Scope)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.Endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("create client-credentials request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(s.ClientID, s.ClientSecret)
	response, err := s.Client.Do(request)
	if err != nil {
		return "", fmt.Errorf("acquire workload token: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if err != nil {
		return "", fmt.Errorf("read workload token response: %w", err)
	}
	if len(body) > 64*1024 {
		return "", errors.New("workload token response is too large")
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("workload token endpoint returned %s", response.Status)
	}
	var result struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("decode workload token: %w", err)
	}
	if result.AccessToken == "" || result.TokenType != "Bearer" || result.ExpiresIn <= 5 || result.ExpiresIn > 300 {
		return "", errors.New("workload token response violates the local profile")
	}
	s.token = result.AccessToken
	s.expires = s.Now().Add(time.Duration(result.ExpiresIn) * time.Second)
	return s.token, nil
}
