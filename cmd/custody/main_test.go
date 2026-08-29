package main

import (
	"strings"
	"testing"

	"github.com/manziman/custody/internal/identity"
)

func TestAuthorizationURLCarriesPKCEStateAndNonce(t *testing.T) {
	t.Parallel()

	flow := identity.PKCE{Challenge: "challenge", Method: "S256", State: "state", Nonce: "nonce"}
	location, err := authorizationURL("http://identity/authorize", flow)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"response_type=code", "code_challenge=challenge", "code_challenge_method=S256", "state=state", "nonce=nonce"} {
		if !strings.Contains(location, fragment) {
			t.Fatalf("authorization URL %q lacks %q", location, fragment)
		}
	}
}
