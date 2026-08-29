package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/manziman/custody/internal/identity"
)

const (
	loginIssuer      = "http://127.0.0.1:8080/realms/custody"
	loginRedirectURI = "http://127.0.0.1:8787/callback"
)

type callbackResult struct {
	code string
	err  error
}

func runLogin(stdout, stderr io.Writer) int {
	flow, err := identity.NewPKCE()
	if err != nil {
		fmt.Fprintln(stderr, "login:", err)
		return 1
	}
	listener, err := net.Listen("tcp", "127.0.0.1:8787")
	if err != nil {
		fmt.Fprintln(stderr, "login: callback listener:", err)
		return 1
	}
	results := make(chan callbackResult, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /callback", func(w http.ResponseWriter, r *http.Request) {
		if oauthError := r.URL.Query().Get("error"); oauthError != "" {
			results <- callbackResult{err: fmt.Errorf("authorization failed: %s", oauthError)}
			http.Error(w, "Authorization failed. Return to the terminal.", http.StatusBadRequest)
			return
		}
		code := r.URL.Query().Get("code")
		if err := flow.ValidateCallback(r.URL.Query().Get("state"), code); err != nil {
			results <- callbackResult{err: err}
			http.Error(w, "Invalid callback. Return to the terminal.", http.StatusBadRequest)
			return
		}
		results <- callbackResult{code: code}
		_, _ = io.WriteString(w, "Custody login complete. You can return to the terminal.\n")
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()

	location, err := authorizationURL(loginIssuer+"/protocol/openid-connect/auth", flow)
	if err != nil {
		fmt.Fprintln(stderr, "login:", err)
		return 1
	}
	fmt.Fprintln(stdout, "Open this URL in your browser:")
	fmt.Fprintln(stdout, location)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var callback callbackResult
	select {
	case callback = <-results:
	case <-ctx.Done():
		fmt.Fprintln(stderr, "login: callback timed out")
		return 1
	}
	_ = server.Shutdown(context.Background())
	if callback.err != nil {
		fmt.Fprintln(stderr, "login:", callback.err)
		return 1
	}

	tokens, err := exchangeAuthorizationCode(ctx, callback.code, flow.Verifier)
	if err != nil {
		fmt.Fprintln(stderr, "login:", err)
		return 1
	}
	client := &http.Client{Timeout: 10 * time.Second}
	idVerifier := &identity.RemoteVerifier{
		Issuer: loginIssuer, Audience: "custody-cli",
		JWKSURL: loginIssuer + "/protocol/openid-connect/certs", Client: client,
		Now: time.Now, Skew: 5 * time.Second,
	}
	if err := idVerifier.Refresh(ctx); err != nil {
		fmt.Fprintln(stderr, "login: fetch signing keys:", err)
		return 1
	}
	if _, err := idVerifier.VerifyNonce(tokens.IDToken, flow.Nonce); err != nil {
		fmt.Fprintln(stderr, "login: validate ID token:", err)
		return 1
	}
	accessVerifier := &identity.RemoteVerifier{
		Issuer: loginIssuer, Audience: "custody-tts",
		JWKSURL: loginIssuer + "/protocol/openid-connect/certs", Client: client,
		Now: time.Now, Skew: 5 * time.Second,
	}
	if err := accessVerifier.Refresh(ctx); err != nil {
		fmt.Fprintln(stderr, "login: fetch access-token signing keys:", err)
		return 1
	}
	if _, err := accessVerifier.Verify(tokens.AccessToken); err != nil {
		fmt.Fprintln(stderr, "login: validate access token:", err)
		return 1
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://127.0.0.1:8085/run", nil)
	if err != nil {
		fmt.Fprintln(stderr, "login:", err)
		return 1
	}
	request.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	response, err := client.Do(request)
	if err != nil {
		fmt.Fprintln(stderr, "login: call reference agent:", err)
		return 1
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024+1))
	if err != nil || len(body) > 1024*1024 || response.StatusCode != http.StatusOK {
		fmt.Fprintf(stderr, "login: reference agent returned %s\n", response.Status)
		return 1
	}
	_, _ = stdout.Write(body)
	return 0
}

func authorizationURL(endpoint string, flow identity.PKCE) (string, error) {
	location, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	query := location.Query()
	query.Set("client_id", "custody-cli")
	query.Set("response_type", "code")
	query.Set("redirect_uri", loginRedirectURI)
	query.Set("scope", "openid patient-records.read")
	query.Set("code_challenge", flow.Challenge)
	query.Set("code_challenge_method", flow.Method)
	query.Set("state", flow.State)
	query.Set("nonce", flow.Nonce)
	location.RawQuery = query.Encode()
	return location.String(), nil
}

type oidcTokens struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
}

func exchangeAuthorizationCode(ctx context.Context, code, verifier string) (oidcTokens, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"custody-cli"},
		"redirect_uri":  {loginRedirectURI},
		"code":          {code},
		"code_verifier": {verifier},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, loginIssuer+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		return oidcTokens{}, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
	if err != nil {
		return oidcTokens{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return oidcTokens{}, fmt.Errorf("token endpoint returned %s", response.Status)
	}
	var tokens oidcTokens
	if err := json.NewDecoder(io.LimitReader(response.Body, 64*1024)).Decode(&tokens); err != nil {
		return oidcTokens{}, err
	}
	if tokens.AccessToken == "" || tokens.IDToken == "" || tokens.TokenType != "Bearer" {
		return oidcTokens{}, errors.New("token response is incomplete")
	}
	return tokens, nil
}
