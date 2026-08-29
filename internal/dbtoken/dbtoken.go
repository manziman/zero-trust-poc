// Package dbtoken implements the short-lived OAuth access-token profile used
// exclusively for PostgreSQL OAUTHBEARER authentication.
package dbtoken

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/manziman/custody/internal/authority"
)

const (
	Type       = "at+jwt"
	MaximumTTL = 30 * time.Second

	RolePatientRecordsReader = "custody_patient_records_reader"
	RoleAvailabilityReader   = "custody_schedule_availability_reader"
	RoleAppointmentCreator   = "custody_schedule_appointment_creator"
	RoleOrgExporter          = "custody_org_exporter"
	RolePatientImporter      = "custody_patient_importer"
)

// Access is the authorization context the TTS derives from its authoritative
// subject directory. PostgreSQL binds every field into system_user before RLS
// evaluates a query; callers cannot supply or override this structure.
type Access struct {
	Authority    authority.Context
	Action       string
	DatabaseRole string
}

func (a Access) Validate() error {
	if err := a.Authority.Validate(a.Action); err != nil {
		return err
	}
	wantRole := map[string]string{
		authority.ActionPatientRecordsRead:   RolePatientRecordsReader,
		authority.ActionAvailabilityRead:     RoleAvailabilityReader,
		authority.ActionAppointmentCreate:    RoleAppointmentCreator,
		authority.ActionPatientRecordsExport: RoleOrgExporter,
		authority.ActionPatientRecordsImport: RolePatientImporter,
	}[a.Action]
	if wantRole == "" || a.DatabaseRole != wantRole {
		return errors.New("database action and capability role are inconsistent")
	}
	return nil
}

// IssueRequest contains identity derived from a verified Transaction Token.
type IssueRequest struct {
	TransactionID string
	Subject       string
	Workload      string
	Access        Access
}

// Claims is the complete security-relevant database token profile.
type Claims struct {
	Issuer        string
	Audience      string
	IssuedAt      time.Time
	ExpiresAt     time.Time
	TokenID       string
	TransactionID string
	Subject       string
	Workload      string
	Access
}

// Issuer owns a database-only signing key. It must not share key material or
// issuer metadata with the Transaction Token issuer.
type Issuer struct {
	Issuer     string
	Audience   string
	KeyID      string
	PrivateKey ed25519.PrivateKey
	TTL        time.Duration
	Now        func() time.Time
	NewTokenID func() string
}

func (i Issuer) Issue(request IssueRequest) (string, error) {
	if i.Issuer == "" || i.Audience == "" || i.KeyID == "" || len(i.PrivateKey) != ed25519.PrivateKeySize || i.Now == nil || i.NewTokenID == nil {
		return "", errors.New("database-token issuer configuration is incomplete")
	}
	if i.TTL <= 0 || i.TTL > MaximumTTL {
		return "", fmt.Errorf("database-token TTL must be between zero and %s", MaximumTTL)
	}
	if request.TransactionID == "" || request.Subject == "" || request.Workload == "" {
		return "", errors.New("txn, subject, and workload are required")
	}
	if err := request.Access.Validate(); err != nil {
		return "", err
	}
	tokenID := i.NewTokenID()
	if tokenID == "" {
		return "", errors.New("database-token ID is empty")
	}

	now := i.Now().UTC()
	token := jwt.New()
	for name, value := range map[string]any{
		jwt.IssuerKey:     i.Issuer,
		jwt.AudienceKey:   []string{i.Audience},
		jwt.IssuedAtKey:   now,
		jwt.ExpirationKey: now.Add(i.TTL),
		jwt.JwtIDKey:      tokenID,
		jwt.SubjectKey:    request.Subject,
		"wl":              request.Workload,
		"txn":             request.TransactionID,
		"action":          request.Access.Action,
		"org_id":          request.Access.Authority.OrganizationID,
		"principal_kind":  request.Access.Authority.PrincipalKind,
		"access_profile":  request.Access.Authority.AccessProfile,
		"resource":        request.Access.Authority.Resource,
		"db_role":         request.Access.DatabaseRole,
	} {
		if err := token.Set(name, value); err != nil {
			return "", fmt.Errorf("set %s: %w", name, err)
		}
	}
	if request.Access.Authority.PatientID != "" {
		if err := token.Set("patient_id", request.Access.Authority.PatientID); err != nil {
			return "", fmt.Errorf("set patient_id: %w", err)
		}
	}
	if request.Access.Authority.ProviderID != "" {
		if err := token.Set("provider_id", request.Access.Authority.ProviderID); err != nil {
			return "", fmt.Errorf("set provider_id: %w", err)
		}
	}
	if request.Access.Authority.Actor != "" {
		if err := token.Set("act", map[string]any{"sub": request.Access.Authority.Actor}); err != nil {
			return "", fmt.Errorf("set act: %w", err)
		}
	}
	headers := jws.NewHeaders()
	if err := headers.Set(jws.TypeKey, Type); err != nil {
		return "", err
	}
	if err := headers.Set(jws.KeyIDKey, i.KeyID); err != nil {
		return "", err
	}
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.EdDSA(), i.PrivateKey, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return "", fmt.Errorf("sign database token: %w", err)
	}
	return string(signed), nil
}

// Verifier validates the exact database-access profile. It cannot accept a
// Transaction Token because type, issuer, audience, and claims all differ.
type Verifier struct {
	Issuer    string
	Audience  string
	KeyID     string
	PublicKey ed25519.PublicKey
	Now       func() time.Time
	Skew      time.Duration
}

func (v Verifier) Verify(compact string) (Claims, error) {
	if compact == "" || len(compact) > 16*1024 {
		return Claims{}, errors.New("database token size is invalid")
	}
	if v.Issuer == "" || v.Audience == "" || v.KeyID == "" || len(v.PublicKey) != ed25519.PublicKeySize || v.Now == nil {
		return Claims{}, errors.New("database-token verifier configuration is incomplete")
	}
	message, err := jws.Parse([]byte(compact))
	if err != nil || len(message.Signatures()) != 1 {
		return Claims{}, errors.New("database token must contain exactly one JWS signature")
	}
	headers := message.Signatures()[0].ProtectedHeaders()
	algorithm, ok := headers.Algorithm()
	if !ok || algorithm != jwa.EdDSA() {
		return Claims{}, errors.New("database token algorithm must be EdDSA")
	}
	typ, ok := headers.Type()
	if !ok || typ != Type {
		return Claims{}, fmt.Errorf("database token typ must be %q", Type)
	}
	kid, ok := headers.KeyID()
	if !ok || kid != v.KeyID {
		return Claims{}, errors.New("database token key ID is not trusted")
	}

	token, err := jwt.Parse(
		[]byte(compact),
		jwt.WithKey(jwa.EdDSA(), v.PublicKey),
		jwt.WithIssuer(v.Issuer),
		jwt.WithAudience(v.Audience),
		jwt.WithClock(jwt.ClockFunc(v.Now)),
		jwt.WithAcceptableSkew(v.Skew),
		jwt.WithRequiredClaim(jwt.SubjectKey),
		jwt.WithRequiredClaim(jwt.IssuedAtKey),
		jwt.WithRequiredClaim(jwt.ExpirationKey),
		jwt.WithRequiredClaim(jwt.JwtIDKey),
		jwt.WithRequiredClaim("wl"),
		jwt.WithRequiredClaim("txn"),
		jwt.WithRequiredClaim("action"),
		jwt.WithRequiredClaim("org_id"),
		jwt.WithRequiredClaim("principal_kind"),
		jwt.WithRequiredClaim("access_profile"),
		jwt.WithRequiredClaim("resource"),
		jwt.WithRequiredClaim("db_role"),
	)
	if err != nil {
		return Claims{}, fmt.Errorf("verify database token: %w", err)
	}

	claims := Claims{Issuer: v.Issuer, Audience: v.Audience}
	claims.Subject, _ = token.Subject()
	claims.IssuedAt, _ = token.IssuedAt()
	claims.ExpiresAt, _ = token.Expiration()
	claims.TokenID, _ = token.JwtID()
	if claims.ExpiresAt.Sub(claims.IssuedAt) > MaximumTTL {
		return Claims{}, errors.New("database-token lifetime exceeds profile maximum")
	}
	if err := stringClaim(token, "txn", &claims.TransactionID); err != nil {
		return Claims{}, err
	}
	if err := stringClaim(token, "wl", &claims.Workload); err != nil {
		return Claims{}, err
	}
	if err := stringClaim(token, "action", &claims.Action); err != nil {
		return Claims{}, err
	}
	if err := stringClaim(token, "org_id", &claims.Authority.OrganizationID); err != nil {
		return Claims{}, err
	}
	if err := stringClaim(token, "principal_kind", &claims.Authority.PrincipalKind); err != nil {
		return Claims{}, err
	}
	if err := stringClaim(token, "access_profile", &claims.Authority.AccessProfile); err != nil {
		return Claims{}, err
	}
	if err := stringClaim(token, "db_role", &claims.DatabaseRole); err != nil {
		return Claims{}, err
	}
	var patientID any
	if err := token.Get("patient_id", &patientID); err == nil {
		claims.Authority.PatientID, _ = patientID.(string)
	}
	var providerID any
	if err := token.Get("provider_id", &providerID); err == nil {
		claims.Authority.ProviderID, _ = providerID.(string)
	}
	var actor map[string]any
	if err := token.Get("act", &actor); err == nil {
		claims.Authority.Actor, _ = actor["sub"].(string)
		if claims.Authority.Actor == "" {
			return Claims{}, errors.New("database-token actor subject is invalid")
		}
	}
	var resource map[string]any
	if err := token.Get("resource", &resource); err != nil {
		return Claims{}, errors.New("database-token resource is invalid")
	}
	if value, ok := resource["provider_id"]; ok {
		claims.Authority.Resource.ProviderID, _ = value.(string)
	}
	if value, ok := resource["patient_id"]; ok {
		claims.Authority.Resource.PatientID, _ = value.(string)
	}
	if value, ok := resource["slot_id"]; ok {
		claims.Authority.Resource.SlotID, _ = value.(string)
	}
	if claims.Subject == "" || claims.TokenID == "" {
		return Claims{}, errors.New("database-token subject and ID are required")
	}
	if err := claims.Access.Validate(); err != nil {
		return Claims{}, err
	}
	return claims, nil
}

func stringClaim(token jwt.Token, name string, destination *string) error {
	var value any
	if err := token.Get(name, &value); err != nil {
		return fmt.Errorf("missing %s claim", name)
	}
	text, ok := value.(string)
	if !ok || text == "" {
		return fmt.Errorf("%s claim must be a non-empty string", name)
	}
	*destination = text
	return nil
}
