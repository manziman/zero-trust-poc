// Package authority defines the security vocabulary shared by policy, tokens,
// and PostgreSQL. Identity kind and access profile are deliberately separate:
// a human, autonomous agent, or external machine can be granted the same
// bounded row-level profile without pretending to be the same kind of actor.
package authority

import (
	"errors"
	"fmt"
	"regexp"
)

const (
	KindHuman           = "human"
	KindAutonomousAgent = "autonomous_agent"
	KindExternalMachine = "external_machine"

	ProfilePatientSelf      = "patient_self"
	ProfileProviderAssigned = "provider_assigned"
	ProfileOrgScoped        = "org_scoped"

	ActionPatientRecordsRead   = "patient-records.read"
	ActionAvailabilityRead     = "schedule.availability.read"
	ActionAppointmentCreate    = "schedule.appointment.create"
	ActionPatientRecordsExport = "patient-records.export"
	ActionPatientRecordsImport = "patient-records.import"
)

var (
	uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	idPattern   = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)
)

// Resource is the signed target of one business operation. Empty fields are
// not wildcards: ValidateForAction defines the exact shape allowed per action.
type Resource struct {
	ProviderID string `json:"provider_id,omitempty"`
	PatientID  string `json:"patient_id,omitempty"`
	SlotID     string `json:"slot_id,omitempty"`
}

// Context is produced only by the authorization catalog after evaluating an
// authenticated principal, requesting workload, action, and resource.
type Context struct {
	PrincipalKind  string
	AccessProfile  string
	OrganizationID string
	PatientID      string
	ProviderID     string
	Actor          string
	Resource       Resource
}

func (c Context) Validate(action string) error {
	if !uuidPattern.MatchString(c.OrganizationID) {
		return errors.New("authority organization ID is invalid")
	}
	if c.PrincipalKind != KindHuman && c.PrincipalKind != KindAutonomousAgent && c.PrincipalKind != KindExternalMachine {
		return errors.New("authority principal kind is invalid")
	}
	switch c.AccessProfile {
	case ProfilePatientSelf:
		if !validID(c.PatientID) {
			return errors.New("patient-self authority requires a patient ID")
		}
	case ProfileProviderAssigned:
		if !validID(c.ProviderID) {
			return errors.New("provider-assigned authority requires a provider ID")
		}
	case ProfileOrgScoped:
	default:
		return errors.New("authority access profile is invalid")
	}
	if err := c.Resource.ValidateForAction(action); err != nil {
		return err
	}
	return nil
}

func (r Resource) ValidateForAction(action string) error {
	switch action {
	case ActionPatientRecordsRead, ActionPatientRecordsExport:
		if r != (Resource{}) {
			return errors.New("patient record action does not accept a caller-selected resource")
		}
	case ActionAvailabilityRead:
		if !validID(r.ProviderID) || r.PatientID != "" || r.SlotID != "" {
			return errors.New("availability resource must contain only a provider ID")
		}
	case ActionAppointmentCreate:
		if !validID(r.ProviderID) || !validID(r.SlotID) || r.PatientID != "" {
			return errors.New("appointment resource must contain provider and slot IDs")
		}
	case ActionPatientRecordsImport:
		if !validID(r.PatientID) || r.ProviderID != "" || r.SlotID != "" {
			return errors.New("import resource must contain only a patient ID")
		}
	default:
		return fmt.Errorf("unsupported action %q", action)
	}
	return nil
}

func validID(value string) bool { return idPattern.MatchString(value) }
