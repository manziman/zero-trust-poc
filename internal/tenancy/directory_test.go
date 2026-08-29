package tenancy_test

import (
	"testing"

	"github.com/manziman/custody/internal/authority"
	"github.com/manziman/custody/internal/dbtoken"
	"github.com/manziman/custody/internal/tenancy"
	"github.com/manziman/custody/internal/txntoken"
)

func TestDemoDirectorySeparatesIdentityKindFromAccessProfile(t *testing.T) {
	t.Parallel()
	tests := []struct {
		subject, workload, action string
		resource                  authority.Resource
		kind, profile, role       string
	}{
		{"demo-patient", "demo-app", authority.ActionPatientRecordsRead, authority.Resource{}, authority.KindHuman, authority.ProfilePatientSelf, dbtoken.RolePatientRecordsReader},
		{"11111111-1111-4111-8111-111111111111", "agent-42", authority.ActionPatientRecordsRead, authority.Resource{}, authority.KindHuman, authority.ProfilePatientSelf, dbtoken.RolePatientRecordsReader},
		{"automation-principal", "automation-principal", authority.ActionPatientRecordsRead, authority.Resource{}, authority.KindAutonomousAgent, authority.ProfileProviderAssigned, dbtoken.RolePatientRecordsReader},
		{"external-exporter", "external-exporter", authority.ActionPatientRecordsExport, authority.Resource{}, authority.KindExternalMachine, authority.ProfileOrgScoped, dbtoken.RoleOrgExporter},
		{"demo-patient", "agent-42", authority.ActionAppointmentCreate, authority.Resource{ProviderID: "17", SlotID: "812"}, authority.KindHuman, authority.ProfilePatientSelf, dbtoken.RoleAppointmentCreator},
	}
	for _, test := range tests {
		authorized, err := tenancy.DemoDirectory().Authorize(test.subject, test.workload, test.action, test.resource)
		if err != nil {
			t.Fatalf("authorize %s: %v", test.subject, err)
		}
		claims := txntoken.Claims{Subject: test.subject, RequestingWorkload: test.workload, Action: test.action,
			PrincipalKind: authorized.PrincipalKind, AccessProfile: authorized.AccessProfile,
			OrganizationID: authorized.OrganizationID, PatientID: authorized.PatientID, ProviderID: authorized.ProviderID,
			Actor: authorized.Actor, Resource: authorized.Resource}
		access, err := tenancy.DemoDirectory().DatabaseAccess(claims)
		if err != nil {
			t.Fatal(err)
		}
		if access.Authority.PrincipalKind != test.kind || access.Authority.AccessProfile != test.profile || access.DatabaseRole != test.role {
			t.Fatalf("access = %#v", access)
		}
	}
}

func TestDemoDirectoryRejectsEscalationAndResourceSubstitution(t *testing.T) {
	t.Parallel()
	directory := tenancy.DemoDirectory()
	if _, err := directory.Authorize("automation-principal", "automation-principal", authority.ActionPatientRecordsExport, authority.Resource{}); err == nil {
		t.Fatal("autonomous agent escalated to organization export")
	}
	if _, err := directory.Authorize("demo-patient", "agent-42", authority.ActionAppointmentCreate, authority.Resource{ProviderID: "17", SlotID: "999"}); err == nil {
		t.Fatal("agent substituted an unauthorized slot")
	}
	if _, err := directory.Authorize("unknown", "demo-app", authority.ActionPatientRecordsRead, authority.Resource{}); err == nil {
		t.Fatal("unknown subject received authority")
	}
}
