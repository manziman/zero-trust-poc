// Command demo runs the four Phase 2 authority paths through the same token
// pipeline and PostgreSQL OAuth/RLS boundary. It prints security-relevant
// decisions without ever printing raw credentials.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/manziman/custody/internal/authority"
	"github.com/manziman/custody/internal/workload"
)

const tokenEndpoint = "http://keycloak:8080/realms/custody/protocol/openid-connect/token"

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 15 * time.Second}

	fmt.Println("\n[demo] Phase 2: authority belongs to principals; workloads have no standing patient-data role")
	appToken := mustToken(ctx, client, "demo-app", os.Getenv("CUSTODY_DEMO_APP_CLIENT_SECRET"))
	direct := []struct {
		name, clientID, secret string
		expected               []int
	}{
		{"organization administrator", "demo-org-admin", os.Getenv("CUSTODY_DEMO_ORG_ADMIN_CLIENT_SECRET"), []int{101, 102, 103}},
		{"assigned provider 17", "demo-provider", os.Getenv("CUSTODY_DEMO_PROVIDER_CLIENT_SECRET"), []int{101, 102}},
		{"patient 101", "demo-patient", os.Getenv("CUSTODY_DEMO_PATIENT_CLIENT_SECRET"), []int{101}},
	}
	for _, item := range direct {
		subject := mustToken(ctx, client, item.clientID, item.secret)
		if err := runRecords(ctx, client, "direct end user: "+item.name, subject, appToken, authority.ActionPatientRecordsRead, item.expected); err != nil {
			fail(err)
		}
	}

	patient := mustToken(ctx, client, "demo-patient", os.Getenv("CUSTODY_DEMO_PATIENT_CLIENT_SECRET"))
	if err := runDelegatedScheduling(ctx, client, patient); err != nil {
		fail(err)
	}

	autonomous := mustToken(ctx, client, "automation-principal", os.Getenv("CUSTODY_AUTOMATION_CLIENT_SECRET"))
	if err := runRecords(ctx, client, "autonomous agent: provider-scoped automation", autonomous, autonomous, authority.ActionPatientRecordsRead, []int{101, 102}); err != nil {
		fail(err)
	}

	external := mustToken(ctx, client, "external-exporter", os.Getenv("CUSTODY_EXTERNAL_EXPORTER_CLIENT_SECRET"))
	if err := runRecords(ctx, client, "external API machine: organization export", external, external, authority.ActionPatientRecordsExport, []int{101, 102, 103}); err != nil {
		fail(err)
	}
	fmt.Println("\n[demo] PASS: all four principal paths were capability-limited and directly attributable")
}

func runRecords(ctx context.Context, client *http.Client, label, subjectToken, workloadToken, action string, expected []int) error {
	fmt.Printf("\n[demo] path=%s\n", label)
	fmt.Printf("[demo] request action=%s resource={} (no database role supplied by caller)\n", action)
	txnToken, claims, err := exchange(ctx, client, subjectToken, workloadToken, action, authority.Resource{})
	if err != nil {
		return err
	}
	writeAuthority(claims)
	body, err := gateway(ctx, client, workloadToken, txnToken, http.MethodGet, "/patient-records?ids=101,102,103,201")
	if err != nil {
		return err
	}
	var records []struct {
		ID int `json:"id"`
	}
	if err := json.Unmarshal(body, &records); err != nil {
		return err
	}
	if err := validateRecordIDs(records, expected); err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	fmt.Printf("[demo] PostgreSQL authenticated the short-lived database token and RLS returned ids=%v from requested ids=[101 102 103 201]; txn=%s\n", expected, claims.TransactionID)
	return nil
}

func runDelegatedScheduling(ctx context.Context, client *http.Client, subjectToken string) error {
	fmt.Println("\n[demo] path=user through agent: patient 101 delegates scheduling to chat agent-42")
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://agent:8085/schedule", nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+subjectToken)
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024))
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("agent scheduling returned %s: %s", response.Status, body)
	}
	var result struct {
		AvailabilityTransaction string `json:"availability_txn"`
		AppointmentTransaction  string `json:"appointment_txn"`
		Availability            []struct {
			SlotID     int `json:"slot_id"`
			ProviderID int `json:"provider_id"`
		} `json:"availability"`
		Appointment struct {
			PatientID  int    `json:"patient_id"`
			ProviderID int    `json:"provider_id"`
			SlotID     int    `json:"slot_id"`
			Status     string `json:"status"`
		} `json:"appointment"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return err
	}
	for _, slot := range result.Availability {
		if slot.ProviderID != 17 {
			return fmt.Errorf("availability leaked provider %d", slot.ProviderID)
		}
	}
	if result.Appointment.PatientID != 101 || result.Appointment.ProviderID != 17 || result.Appointment.SlotID != 812 || result.Appointment.Status != "scheduled" {
		return fmt.Errorf("database returned unexpected appointment: %s", body)
	}
	fmt.Printf("[demo] availability transaction disclosed only public provider-17 slots; txn=%s\n", result.AvailabilityTransaction)
	fmt.Printf("[demo] separate create transaction scheduled patient=101 provider=17 slot=812; txn=%s\n", result.AppointmentTransaction)
	fmt.Println("[demo] the chat agent held no database role; each operation used separately scoped authority")
	return nil
}

type displayClaims struct {
	TransactionID      string             `json:"txn"`
	Subject            string             `json:"sub"`
	RequestingWorkload string             `json:"req_wl"`
	Action             string             `json:"action"`
	PrincipalKind      string             `json:"principal_kind"`
	AccessProfile      string             `json:"access_profile"`
	OrganizationID     string             `json:"org_id"`
	PatientID          string             `json:"patient_id"`
	ProviderID         string             `json:"provider_id"`
	Resource           authority.Resource `json:"resource"`
	Actor              struct {
		Subject string `json:"sub"`
	} `json:"act"`
}

func exchange(ctx context.Context, client *http.Client, subjectToken, workloadToken, action string, resource authority.Resource) (string, displayClaims, error) {
	encodedResource, _ := json.Marshal(resource)
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "audience": {"custody.local"},
		"action": {action}, "resource": {string(encodedResource)},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:txn_token"},
		"subject_token":        {subjectToken}, "subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://tts:8081/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", displayClaims{}, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Authorization", "Bearer "+workloadToken)
	response, err := client.Do(request)
	if err != nil {
		return "", displayClaims{}, err
	}
	defer response.Body.Close()
	var result struct {
		AccessToken string `json:"access_token"`
	}
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 64*1024))
		return "", displayClaims{}, fmt.Errorf("transaction exchange returned %s: %s", response.Status, body)
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil || result.AccessToken == "" {
		return "", displayClaims{}, errors.New("transaction exchange returned an invalid response")
	}
	// Decode only to narrate what the signed token contains. The gateway and TTS
	// validate it cryptographically; PostgreSQL validates the derived database
	// token and makes the final role/RLS decision.
	parts := strings.Split(result.AccessToken, ".")
	if len(parts) != 3 {
		return "", displayClaims{}, errors.New("transaction token is malformed")
	}
	var claims displayClaims
	payload, err := decodeBase64URL(parts[1])
	if err != nil || json.Unmarshal(payload, &claims) != nil || claims.TransactionID == "" {
		return "", displayClaims{}, errors.New("transaction token has no displayable transaction ID")
	}
	return result.AccessToken, claims, nil
}

func gateway(ctx context.Context, client *http.Client, workloadToken, txnToken, method, path string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, method, "http://gateway:8082"+path, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+workloadToken)
	request.Header.Set("Txn-Token", txnToken)
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024))
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gateway returned %s: %s", response.Status, body)
	}
	return body, nil
}

func mustToken(ctx context.Context, client *http.Client, clientID, secret string) string {
	token, err := (&workload.TokenSource{Endpoint: tokenEndpoint, ClientID: clientID, ClientSecret: secret, Client: client, Now: time.Now}).Token(ctx)
	if err != nil {
		fail(fmt.Errorf("acquire %s token: %w", clientID, err))
	}
	return token
}

func validateRecordIDs(records []struct {
	ID int `json:"id"`
}, expected []int) error {
	if len(records) != len(expected) {
		return fmt.Errorf("RLS returned %d records, want %d", len(records), len(expected))
	}
	for index := range expected {
		if records[index].ID != expected[index] {
			return fmt.Errorf("RLS returned id %d at position %d, want %d", records[index].ID, index, expected[index])
		}
	}
	return nil
}

func writeAuthority(claims displayClaims) {
	actor := claims.Actor.Subject
	if actor == "" {
		actor = "none"
	}
	fmt.Printf("[demo] TTS issued txn=%s subject=%s actor=%s requesting_workload=%s\n", claims.TransactionID, claims.Subject, actor, claims.RequestingWorkload)
	fmt.Printf("[demo] signed authority kind=%s profile=%s org=%s patient=%s provider=%s action=%s resource=%+v\n",
		claims.PrincipalKind, claims.AccessProfile, claims.OrganizationID, emptyAsNone(claims.PatientID), emptyAsNone(claims.ProviderID), claims.Action, claims.Resource)
	fmt.Println("[demo] gateway validates workload binding plus action/resource binding; resource forwards the token opaquely")
}

func emptyAsNone(value string) string {
	if value == "" {
		return "none"
	}
	return value
}

func decodeBase64URL(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(value)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
