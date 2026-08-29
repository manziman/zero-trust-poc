// Package tenancy is the authoritative demo entitlement catalog. It has no
// API for selecting access profiles, tenants, or database roles: callers name
// a business action and resource, and the catalog either returns attenuated
// authority or denies the request.
package tenancy

import (
	"errors"

	"github.com/manziman/custody/internal/authority"
	"github.com/manziman/custody/internal/dbtoken"
	"github.com/manziman/custody/internal/txntoken"
)

const DemoOrganizationID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

const interactivePatientSubject = "11111111-1111-4111-8111-111111111111"

type Directory struct{}

func DemoDirectory() Directory { return Directory{} }

type profile struct {
	kind       string
	access     string
	patientID  string
	providerID string
	actions    map[string]bool
}

var demoProfiles = map[string]profile{
	interactivePatientSubject: {kind: authority.KindHuman, access: authority.ProfilePatientSelf, patientID: "101", actions: set(authority.ActionPatientRecordsRead, authority.ActionAvailabilityRead, authority.ActionAppointmentCreate)},
	"demo-org-admin":          {kind: authority.KindHuman, access: authority.ProfileOrgScoped, actions: set(authority.ActionPatientRecordsRead)},
	"demo-provider":           {kind: authority.KindHuman, access: authority.ProfileProviderAssigned, providerID: "17", actions: set(authority.ActionPatientRecordsRead)},
	"demo-patient":            {kind: authority.KindHuman, access: authority.ProfilePatientSelf, patientID: "101", actions: set(authority.ActionPatientRecordsRead, authority.ActionAvailabilityRead, authority.ActionAppointmentCreate)},
	"automation-principal":    {kind: authority.KindAutonomousAgent, access: authority.ProfileProviderAssigned, providerID: "17", actions: set(authority.ActionPatientRecordsRead)},
	"external-exporter":       {kind: authority.KindExternalMachine, access: authority.ProfileOrgScoped, actions: set(authority.ActionPatientRecordsExport)},
}

// Authorize evaluates the demo policy and constructs the complete context that
// is signed into a Transaction Token. The agent is recorded only when it is
// exercising delegated discretion for the human patient.
func (Directory) Authorize(subject, workload, action string, resource authority.Resource) (authority.Context, error) {
	profile, ok := demoProfiles[subject]
	if !ok || !profile.actions[action] {
		return authority.Context{}, errors.New("principal is not granted the requested action")
	}
	if err := resource.ValidateForAction(action); err != nil {
		return authority.Context{}, err
	}
	context := authority.Context{
		PrincipalKind: profile.kind, AccessProfile: profile.access,
		OrganizationID: DemoOrganizationID, PatientID: profile.patientID,
		ProviderID: profile.providerID, Resource: resource,
	}
	if workload == "agent-42" {
		if !isDemoPatient(subject) {
			return authority.Context{}, errors.New("chat agent delegation is provisioned only for the demo patient")
		}
		context.Actor = workload
	}
	if action == authority.ActionAvailabilityRead || action == authority.ActionAppointmentCreate {
		if !isDemoPatient(subject) || workload != "agent-42" || resource.ProviderID != "17" {
			return authority.Context{}, errors.New("scheduling request exceeds delegated patient authority")
		}
	}
	if action == authority.ActionAppointmentCreate && resource.SlotID != "812" {
		return authority.Context{}, errors.New("appointment slot is not authorized")
	}
	if err := context.Validate(action); err != nil {
		return authority.Context{}, err
	}
	return context, nil
}

func isDemoPatient(subject string) bool {
	return subject == "demo-patient" || subject == interactivePatientSubject
}

// DatabaseAccess maps authenticated, signed transaction claims to a concrete
// capability role. This mapping is private to TTS and cannot be influenced by
// a caller-visible role parameter.
func (Directory) DatabaseAccess(claims txntoken.Claims) (dbtoken.Access, error) {
	context := authority.Context{
		PrincipalKind: claims.PrincipalKind, AccessProfile: claims.AccessProfile,
		OrganizationID: claims.OrganizationID, PatientID: claims.PatientID,
		ProviderID: claims.ProviderID, Actor: claims.Actor, Resource: claims.Resource,
	}
	role := map[string]string{
		authority.ActionPatientRecordsRead:   dbtoken.RolePatientRecordsReader,
		authority.ActionAvailabilityRead:     dbtoken.RoleAvailabilityReader,
		authority.ActionAppointmentCreate:    dbtoken.RoleAppointmentCreator,
		authority.ActionPatientRecordsExport: dbtoken.RoleOrgExporter,
		authority.ActionPatientRecordsImport: dbtoken.RolePatientImporter,
	}[claims.Action]
	access := dbtoken.Access{Authority: context, Action: claims.Action, DatabaseRole: role}
	if role == "" || access.Validate() != nil {
		return dbtoken.Access{}, errors.New("transaction has no database capability")
	}
	return access, nil
}

func set(values ...string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}
