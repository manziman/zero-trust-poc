package identity

import (
	"encoding/base64"
	"testing"
)

func TestNewPKCEUsesS256AndHighEntropyState(t *testing.T) {
	t.Parallel()

	flow, err := NewPKCE()
	if err != nil {
		t.Fatalf("NewPKCE() error = %v", err)
	}
	if flow.Method != "S256" {
		t.Fatalf("method = %q", flow.Method)
	}
	if len(flow.Verifier) < 43 || len(flow.Verifier) > 128 {
		t.Fatalf("verifier length = %d", len(flow.Verifier))
	}
	if flow.Challenge == flow.Verifier || flow.Challenge == "" {
		t.Fatalf("challenge was not derived from verifier")
	}
	if flow.State == "" || flow.Nonce == "" || flow.State == flow.Nonce {
		t.Fatalf("state and nonce must be independent")
	}
	for name, value := range map[string]string{
		"verifier":  flow.Verifier,
		"challenge": flow.Challenge,
		"state":     flow.State,
		"nonce":     flow.Nonce,
	} {
		if _, err := base64.RawURLEncoding.DecodeString(value); err != nil {
			t.Fatalf("%s is not unpadded base64url: %v", name, err)
		}
	}
}

func TestPKCECallbackRejectsStateMismatch(t *testing.T) {
	t.Parallel()

	flow, err := NewPKCE()
	if err != nil {
		t.Fatal(err)
	}
	if err := flow.ValidateCallback("different", "code"); err == nil {
		t.Fatal("state mismatch accepted")
	}
	if err := flow.ValidateCallback(flow.State, ""); err == nil {
		t.Fatal("empty authorization code accepted")
	}
	if err := flow.ValidateCallback(flow.State, "code"); err != nil {
		t.Fatalf("valid callback rejected: %v", err)
	}
}
