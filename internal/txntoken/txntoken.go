// Package txntoken implements Custody's pinned profile of
// draft-ietf-oauth-transaction-tokens-11. Transaction Tokens are carried in
// Txn-Token and must never be used as OAuth access tokens.
package txntoken

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
	Type       = "txntoken+jwt"
	MaximumTTL = time.Minute
)

// IssueRequest contains identity derived from verified credentials and
// context accepted by the TTS. Callers must not populate it from unverified
// request fields.
type IssueRequest struct {
	TransactionID      string
	Subject            string
	Workload           string
	Action             string
	Authority          authority.Context
	TransactionContext map[string]any
	RequestContext     map[string]any
}

// Claims is the stable subset of the draft-11 claims used by downstream
// Custody workloads.
type Claims struct {
	Issuer             string
	Audience           string
	IssuedAt           time.Time
	ExpiresAt          time.Time
	TransactionID      string
	Subject            string
	RequestingWorkload string
	Action             string
	PrincipalKind      string
	AccessProfile      string
	OrganizationID     string
	PatientID          string
	ProviderID         string
	Actor              string
	Resource           authority.Resource
	TransactionContext map[string]any
	RequestContext     map[string]any
}

// Issuer signs one short-lived Transaction Token profile.
type Issuer struct {
	Issuer     string
	Audience   string
	KeyID      string
	PrivateKey ed25519.PrivateKey
	TTL        time.Duration
	Now        func() time.Time
}

// Issue creates a compact EdDSA JWS with the required draft-11 claims.
func (i Issuer) Issue(request IssueRequest) (string, error) {
	if err := i.validate(); err != nil {
		return "", err
	}
	if request.TransactionID == "" || request.Subject == "" || request.Workload == "" || request.Action == "" {
		return "", errors.New("txn, subject, workload, and action are required")
	}
	if err := request.Authority.Validate(request.Action); err != nil {
		return "", err
	}

	now := i.Now().UTC()
	token := jwt.New()
	for name, value := range map[string]any{
		jwt.IssuerKey:     i.Issuer,
		jwt.AudienceKey:   []string{i.Audience},
		jwt.IssuedAtKey:   now,
		jwt.ExpirationKey: now.Add(i.TTL),
		jwt.SubjectKey:    request.Subject,
		"txn":             request.TransactionID,
		"req_wl":          request.Workload,
		"action":          request.Action,
		"principal_kind":  request.Authority.PrincipalKind,
		"access_profile":  request.Authority.AccessProfile,
		"org_id":          request.Authority.OrganizationID,
		"resource":        request.Authority.Resource,
	} {
		if err := token.Set(name, value); err != nil {
			return "", fmt.Errorf("set %s: %w", name, err)
		}
	}
	if request.Authority.PatientID != "" {
		_ = token.Set("patient_id", request.Authority.PatientID)
	}
	if request.Authority.ProviderID != "" {
		_ = token.Set("provider_id", request.Authority.ProviderID)
	}
	if request.Authority.Actor != "" {
		_ = token.Set("act", map[string]any{"sub": request.Authority.Actor})
	}
	if request.TransactionContext != nil {
		if err := token.Set("tctx", request.TransactionContext); err != nil {
			return "", fmt.Errorf("set tctx: %w", err)
		}
	}
	if request.RequestContext != nil {
		if err := token.Set("rctx", request.RequestContext); err != nil {
			return "", fmt.Errorf("set rctx: %w", err)
		}
	}

	headers := jws.NewHeaders()
	if err := headers.Set(jws.TypeKey, Type); err != nil {
		return "", fmt.Errorf("set typ: %w", err)
	}
	if err := headers.Set(jws.KeyIDKey, i.KeyID); err != nil {
		return "", fmt.Errorf("set kid: %w", err)
	}
	signed, err := jwt.Sign(token, jwt.WithKey(
		jwa.EdDSA(),
		i.PrivateKey,
		jws.WithProtectedHeaders(headers),
	))
	if err != nil {
		return "", fmt.Errorf("sign transaction token: %w", err)
	}
	return string(signed), nil
}

func (i Issuer) validate() error {
	if i.Issuer == "" || i.Audience == "" || i.KeyID == "" {
		return errors.New("issuer, audience, and key ID are required")
	}
	if len(i.PrivateKey) != ed25519.PrivateKeySize {
		return errors.New("invalid Ed25519 private key")
	}
	if i.TTL <= 0 || i.TTL > MaximumTTL {
		return fmt.Errorf("TTL must be between zero and %s", MaximumTTL)
	}
	if i.Now == nil {
		return errors.New("clock is required")
	}
	return nil
}

// Verifier validates one Transaction Token profile and returns typed claims.
type Verifier struct {
	Issuer    string
	Audience  string
	KeyID     string
	PublicKey ed25519.PublicKey
	Now       func() time.Time
	Skew      time.Duration
}

// Verify authenticates and validates a compact Transaction Token.
func (v Verifier) Verify(compact string) (Claims, error) {
	if len(compact) == 0 || len(compact) > 16*1024 {
		return Claims{}, errors.New("transaction token size is invalid")
	}
	if len(v.PublicKey) != ed25519.PublicKeySize || v.Issuer == "" || v.Audience == "" || v.KeyID == "" || v.Now == nil {
		return Claims{}, errors.New("verifier configuration is incomplete")
	}

	message, err := jws.Parse([]byte(compact))
	if err != nil || len(message.Signatures()) != 1 {
		return Claims{}, errors.New("transaction token must contain exactly one JWS signature")
	}
	headers := message.Signatures()[0].ProtectedHeaders()
	algorithm, ok := headers.Algorithm()
	if !ok || algorithm != jwa.EdDSA() {
		return Claims{}, errors.New("transaction token algorithm must be EdDSA")
	}
	typ, ok := headers.Type()
	if !ok || typ != Type {
		return Claims{}, fmt.Errorf("transaction token typ must be %q", Type)
	}
	kid, ok := headers.KeyID()
	if !ok || kid != v.KeyID {
		return Claims{}, errors.New("transaction token key ID is not trusted")
	}

	token, err := jwt.Parse(
		[]byte(compact),
		jwt.WithKey(jwa.EdDSA(), v.PublicKey),
		jwt.WithIssuer(v.Issuer),
		jwt.WithAudience(v.Audience),
		jwt.WithClock(jwt.ClockFunc(v.Now)),
		jwt.WithAcceptableSkew(v.Skew),
		jwt.WithRequiredClaim(jwt.IssuedAtKey),
		jwt.WithRequiredClaim(jwt.ExpirationKey),
		jwt.WithRequiredClaim(jwt.SubjectKey),
		jwt.WithRequiredClaim("txn"),
		jwt.WithRequiredClaim("req_wl"),
		jwt.WithRequiredClaim("action"),
		jwt.WithRequiredClaim("principal_kind"),
		jwt.WithRequiredClaim("access_profile"),
		jwt.WithRequiredClaim("org_id"),
		jwt.WithRequiredClaim("resource"),
	)
	if err != nil {
		return Claims{}, fmt.Errorf("verify transaction token: %w", err)
	}

	claims := Claims{Issuer: v.Issuer, Audience: v.Audience}
	claims.IssuedAt, _ = token.IssuedAt()
	claims.ExpiresAt, _ = token.Expiration()
	claims.Subject, _ = token.Subject()
	if claims.ExpiresAt.Sub(claims.IssuedAt) > MaximumTTL {
		return Claims{}, errors.New("transaction token lifetime exceeds profile maximum")
	}
	if err := stringClaim(token, "txn", &claims.TransactionID); err != nil {
		return Claims{}, err
	}
	if err := stringClaim(token, "req_wl", &claims.RequestingWorkload); err != nil {
		return Claims{}, err
	}
	if err := stringClaim(token, "action", &claims.Action); err != nil {
		return Claims{}, err
	}
	if err := stringClaim(token, "principal_kind", &claims.PrincipalKind); err != nil {
		return Claims{}, err
	}
	if err := stringClaim(token, "access_profile", &claims.AccessProfile); err != nil {
		return Claims{}, err
	}
	if err := stringClaim(token, "org_id", &claims.OrganizationID); err != nil {
		return Claims{}, err
	}
	optionalStringClaim(token, "patient_id", &claims.PatientID)
	optionalStringClaim(token, "provider_id", &claims.ProviderID)
	var actor map[string]any
	if err := token.Get("act", &actor); err == nil {
		claims.Actor, _ = actor["sub"].(string)
		if claims.Actor == "" {
			return Claims{}, errors.New("transaction-token actor subject is invalid")
		}
	}
	resource, err := resourceClaim(token)
	if err != nil {
		return Claims{}, errors.New("transaction-token resource is invalid")
	}
	claims.Resource = resource
	context := authority.Context{
		PrincipalKind: claims.PrincipalKind, AccessProfile: claims.AccessProfile,
		OrganizationID: claims.OrganizationID, PatientID: claims.PatientID,
		ProviderID: claims.ProviderID, Actor: claims.Actor, Resource: claims.Resource,
	}
	if err := context.Validate(claims.Action); err != nil {
		return Claims{}, err
	}
	claims.TransactionContext = mapClaim(token, "tctx")
	claims.RequestContext = mapClaim(token, "rctx")
	return claims, nil
}

func resourceClaim(token jwt.Token) (authority.Resource, error) {
	var value map[string]any
	if err := token.Get("resource", &value); err != nil {
		return authority.Resource{}, err
	}
	resource := authority.Resource{}
	if field, ok := value["provider_id"]; ok {
		resource.ProviderID, ok = field.(string)
		if !ok {
			return authority.Resource{}, errors.New("provider_id is not a string")
		}
	}
	if field, ok := value["patient_id"]; ok {
		resource.PatientID, ok = field.(string)
		if !ok {
			return authority.Resource{}, errors.New("patient_id is not a string")
		}
	}
	if field, ok := value["slot_id"]; ok {
		resource.SlotID, ok = field.(string)
		if !ok {
			return authority.Resource{}, errors.New("slot_id is not a string")
		}
	}
	return resource, nil
}

func optionalStringClaim(token jwt.Token, name string, destination *string) {
	var value any
	if err := token.Get(name, &value); err == nil {
		*destination, _ = value.(string)
	}
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

func mapClaim(token jwt.Token, name string) map[string]any {
	var value map[string]any
	if err := token.Get(name, &value); err != nil {
		return nil
	}
	return value
}
