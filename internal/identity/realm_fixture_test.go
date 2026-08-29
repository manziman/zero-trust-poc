package identity_test

import (
	"encoding/json"
	"os"
	"testing"
)

type realmFixture struct {
	Realm        string `json:"realm"`
	ClientScopes []struct {
		Name            string `json:"name"`
		ProtocolMappers []struct {
			ProtocolMapper string            `json:"protocolMapper"`
			Config         map[string]string `json:"config"`
		} `json:"protocolMappers"`
	} `json:"clientScopes"`
	Users []struct {
		Username string `json:"username"`
		Email    string `json:"email"`
	} `json:"users"`
	Clients []struct {
		ClientID                  string            `json:"clientId"`
		PublicClient              bool              `json:"publicClient"`
		StandardFlowEnabled       bool              `json:"standardFlowEnabled"`
		DirectAccessGrantsEnabled bool              `json:"directAccessGrantsEnabled"`
		ServiceAccountsEnabled    bool              `json:"serviceAccountsEnabled"`
		FullScopeAllowed          bool              `json:"fullScopeAllowed"`
		Attributes                map[string]string `json:"attributes"`
		DefaultClientScopes       []string          `json:"defaultClientScopes"`
	} `json:"clients"`
}

func TestRealmFixtureSeparatesHumanAndWorkloadFlows(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("../../deploy/keycloak/custody-realm.json")
	if err != nil {
		t.Fatalf("read realm fixture: %v", err)
	}
	var realm realmFixture
	if err := json.Unmarshal(data, &realm); err != nil {
		t.Fatalf("decode realm fixture: %v", err)
	}
	if realm.Realm != "custody" {
		t.Fatalf("realm = %q", realm.Realm)
	}

	clients := make(map[string]struct {
		public, standard, direct, service, full bool
		pkce                                    string
	})
	for _, client := range realm.Clients {
		clients[client.ClientID] = struct {
			public, standard, direct, service, full bool
			pkce                                    string
		}{
			client.PublicClient,
			client.StandardFlowEnabled,
			client.DirectAccessGrantsEnabled,
			client.ServiceAccountsEnabled,
			client.FullScopeAllowed,
			client.Attributes["pkce.code.challenge.method"],
		}
	}

	human := clients["custody-cli"]
	if !human.public || !human.standard || human.direct || human.service || human.pkce != "S256" {
		t.Fatalf("custody-cli configuration = %#v", human)
	}
	var interactiveScopes []string
	for _, client := range realm.Clients {
		if client.ClientID == "custody-cli" {
			interactiveScopes = client.DefaultClientScopes
			break
		}
	}
	if !containsString(interactiveScopes, "custody-subject") {
		t.Fatalf("custody-cli default scopes = %v; custody-subject is required for the access-token sub claim", interactiveScopes)
	}
	if !hasAccessTokenSubjectMapper(realm) {
		t.Fatal("custody-subject scope must declare an access-token Subject (sub) mapper")
	}
	for _, user := range realm.Users {
		if user.Username == "alice" && user.Email == "" {
			t.Fatal("alice requires an email to avoid an interactive profile-update action")
		}
	}
	for _, name := range []string{"agent-42", "gateway", "resource", "automation-principal", "demo-org-admin", "demo-provider", "demo-patient"} {
		workload, ok := clients[name]
		if !ok {
			t.Fatalf("missing workload client %q", name)
		}
		if workload.public || workload.standard || workload.direct || !workload.service || workload.full {
			t.Fatalf("%s configuration = %#v", name, workload)
		}
	}
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func hasAccessTokenSubjectMapper(realm realmFixture) bool {
	for _, scope := range realm.ClientScopes {
		if scope.Name != "custody-subject" {
			continue
		}
		for _, mapper := range scope.ProtocolMappers {
			if mapper.ProtocolMapper == "oidc-sub-mapper" && mapper.Config["access.token.claim"] == "true" {
				return true
			}
		}
	}
	return false
}
