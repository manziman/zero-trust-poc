# Custody Phase 2 Implementation Plan

**Status:** Phase 2A implemented and verified locally; Phase 2B/2C remain planned
**Prepared:** 2026-08-06
**Outcome:** Demonstrate that humans, delegated agents, autonomous internal
agents, and external machines can all be first-class principals whose
transaction-specific authority survives intermediary workloads and is enforced
by PostgreSQL capability roles and row-level policy.

## Implementation record (2026-08-06)

The core vertical slice is implemented. It includes the generalized authority
contract, private action-to-role mapping, operation capability roles, four
principal paths, an opaque data intermediary, provider-only public availability,
and separately authorized race-safe appointment creation. The gateway also
binds the authenticated client to signed `req_wl`; a different approved client
cannot reuse the token.

The demo currently exercises external export (not import) and one autonomous
`provider_assigned` fixture. The importer role and other autonomous profile
shapes are bounded extension points. A separate AuthZEN PDP, approval workflow,
and generated gRPC integration remain Phase 2B/2C rather than being implied by
the Phase 2A result.

## 1. Architectural claim

No application workload has standing patient-data authority. A workload may
temporarily exercise a short-lived database capability derived from an
authenticated principal and an approved business operation, but it cannot
select a tenant, access profile, database role, or broader scope for itself.

The authorization system owns permission decisions. PostgreSQL owns final
enforcement against the actual SQL operation and rows. Workloads between those
boundaries carry authority but do not define it.

## 2. Four principal paths

| Path | Authority subject (`sub`) | Delegated actor (`act`) | Example authority |
|---|---|---|---|
| Direct end user | Human user | None | Patient-self or assigned-provider access |
| User through an agent | Human user | Chat agent | User authority intersected with agent and task limits |
| Autonomous internal agent | Agent identity | None | Explicit org-, provider-, or patient-scoped grant |
| External API user | External machine/client | None by default | Registered import, export, or other API grant |

An API, gateway, scheduling service, or resource service is an execution
workload, not automatically the authority subject. Each workload authenticates
separately at protected boundaries. A workload appears in `act` only
when it exercises delegated discretion, not merely because it forwards bytes.

## 3. Authority vocabulary

Phase 2 separates identity from authorization. The current
`principal_type=org_admin|provider|patient` profile conflates the two and will
be migrated.

| Field | Purpose | Example |
|---|---|---|
| `sub` | Canonical principal identity | `patient-101` |
| `principal_kind` | What the principal is | `human`, `autonomous_agent`, `external_machine` |
| `act` | Optional delegated actor | `chat-agent-42` |
| `org_id` | Signed tenant boundary | `organization-a` |
| `access_profile` | Row-level authority basis | `patient_self`, `provider_assigned`, `org_scoped` |
| `action` | Business operation | `schedule.appointment.create` |
| `resource` | Signed operation target | provider 17, slot 812 |
| `db_capability` | Authorization-system-internal database capability | `appointment_creator` |
| `db_role` | Concrete PostgreSQL role, present only in the database token | `custody_schedule_appointment_creator` |

Callers never submit `db_capability` or `db_role`. They request an action on a
resource. The PDP evaluates that request, and the TTS maps an allow decision to
the database capability and role.

## 4. Why Transaction Tokens remain in the design

A principal token can be exchanged directly for a database token in a
single-service database operation. That is not the primary POC path because
the selected scenarios contain intermediaries: agents, gateways, APIs, and
scheduling/resource services.

The Transaction Token is minted at the first trusted transaction boundary and
replaces propagation of the principal's general-purpose access token. It binds
the principal, optional actor, action, resource, tenant context, and `txn` into
an attenuated internal artifact. The exact token crosses intermediaries and is
exchanged for a 30-second database token only at the last responsible moment.

The database token remains a distinct artifact with a PostgreSQL audience,
separate key, concrete `db_role`, and connection-length lifetime.

## 5. Validation responsibility

Validation is required where a component makes a security decision; it is not
required merely because a token passes through a process.

| Component | Responsibility |
|---|---|
| Transaction ingress/TTS | Validate principal and requesting workload; authorize action/resource; issue Transaction Token |
| Policy gateway/PDP | Validate the token because it makes allow/deny/approval decisions |
| Database-only intermediary | Treat the compact token as opaque and forward it unchanged; do not trust parsed claims |
| Database-token endpoint | Validate Transaction Token and authenticated caller; derive the database capability and role |
| PostgreSQL validator | Validate the database token and exact requested-role consistency |
| PostgreSQL policies | Enforce relation, column, row, and write constraints against actual SQL |

Every intermediary still applies bounded-header handling, strips conflicting
caller-supplied authority headers, avoids credential logging, and authenticates
to the next protected boundary. A service must validate or exchange before any
non-database side effect that PostgreSQL cannot govern, such as publishing a
message or invoking an external scheduling provider.

## 6. Primary delegated-agent scenario: patient scheduling

The patient is the authority subject, the chat agent is the delegated actor,
and the scheduling service is an intermediary workload.

### Availability read

The patient may see only the provider's public bookable slots—not private
calendar entries, appointment identities, notes, or other provider data.

```text
sub              = patient-101
principal_kind   = human
act.sub          = chat-agent-42
org_id           = organization-a
access_profile   = patient_self
action           = schedule.availability.read
resource         = provider-17
db_role          = custody_schedule_availability_reader  # DB token only
```

The role receives `SELECT` only on a safe availability relation. Restrictive
RLS requires the signed organization and target provider.

### Appointment creation

Selecting a slot begins a new authorization transaction. An availability
token cannot create an appointment.

```text
sub              = patient-101
principal_kind   = human
act.sub          = chat-agent-42
org_id           = organization-a
access_profile   = patient_self
action           = schedule.appointment.create
resource         = provider-17 / slot-812
db_role          = custody_schedule_appointment_creator  # DB token only
```

The creation role receives only the minimum insert capability. `WITH CHECK`
policies bind organization, patient, provider, and slot to signed context.
Security-sensitive columns such as patient, organization, creator, and `txn`
are database-derived rather than workload-controlled. Foreign keys, uniqueness,
and overlap constraints make slot allocation race-safe.

## 7. Database capability model

Phase 2 replaces persona-named execution roles with operation capabilities:

```text
custody_patient_records_reader
custody_schedule_availability_reader
custody_schedule_appointment_creator
custody_org_exporter
custody_patient_importer
```

Identity remains individually attributable in `system_user`; `current_user`
states the capability being exercised. RLS combines the capability role with
signed `access_profile` and resource constraints.

The authorization catalog owns mappings such as:

```text
schedule.availability.read  -> availability_reader
schedule.appointment.create -> appointment_creator
patient-records.export      -> org_exporter
patient-records.import      -> patient_importer
```

These mappings are private to the authorization/TTS boundary. Changing a
PostgreSQL role name must not require rebuilding callers.

## 8. Service ergonomics

Do not introduce a semantic sidecar in this phase. A sidecar would require
route- and payload-specific configuration while becoming another
authorization-critical process.

After the hand-written scheduling slice proves the contracts, evaluate gRPC
code generation for mechanics only:

- use the fully qualified RPC method as the canonical action, or annotate it;
- annotate only authorization-relevant resource fields;
- generate client interceptors that obtain or propagate `Txn-Token` metadata;
- generate server plumbing that exposes an opaque transaction handle;
- generate a data-access credential provider that exchanges the token and uses
  the returned `database_user`;
- never generate database roles into consuming clients.

Code generation reduces integration work but does not move policy into API
definitions. The PDP and TTS remain authoritative.

## 9. Workstreams

### A. Contract migration

1. [x] Define versioned principal, actor, action, resource, and access-profile
   contracts.
2. [x] Migrate database tokens from `principal_type` to `principal_kind` plus
   `access_profile`.
3. [x] Keep database roles out of Transaction Token requests and caller-visible
   operation contracts.
4. [x] Add negative fixtures for role injection, tenant injection, action/token
   substitution, and resource substitution.

### B. Authorization catalog and PDP

1. [ ] Add an AuthZEN evaluation boundary for principal/action/resource/context.
2. [x] Provision authoritative fixture grants for all four principal paths.
3. [x] Intersect delegated-human, agent, and requested-task authority.
4. [x] Map only an allow decision to a bounded database capability.
5. [ ] Bind an external decision proof to database-token issuance when the
   in-process catalog is replaced so a
   resource workload cannot bypass the gateway/PDP.

### C. Scheduling data model and enforcement

1. [x] Add providers, safe bookable slots, and appointments.
2. [x] Keep public availability structurally separate from private calendar data.
3. [x] Add capability roles, least-privilege grants, forced RLS, write checks, and
   race-safe scheduling constraints.
4. [x] Make availability and appointment creation separate transaction/database
   token profiles.
5. [x] Prove that wrong action, resource, tenant, profile, and role fail at
   TTS or PostgreSQL.

### D. Four-principal demonstration matrix

1. [x] Direct patient, provider, and org-admin application access.
2. [x] Patient scheduling through a chat agent and scheduling service.
3. [x] An autonomous agent with a provider-scoped profile that
   cannot self-escalate.
4. [x] External machine export with its own integration identity.
5. [x] Signed traces that distinguish authority subject, delegated actor,
   intermediary workloads, database capability, target, and result.

### E. Integration ergonomics

1. Implement a small explicit Go API first.
2. Measure repeated integration code and identify stable seams.
3. Prototype protobuf annotations and generated gRPC interceptors only after
   the explicit API is proven.
4. Keep generic credential custody separate from semantic authorization.

### F. Approval extension

1. Preserve the existing AuthZEN boolean boundary.
2. Add requestable denial and durable approval only after the non-approval
   scheduling path is complete.
3. Require a fresh allow decision containing approval evidence before database
   capability issuance.

## 10. Verification matrix

The Phase 2 demo and tests must prove at least:

| Attempt | Expected enforcement |
|---|---|
| Patient reads chosen provider's bookable slots | Allowed |
| Patient reads provider private calendar or existing appointment identities | Database privilege denial |
| Patient schedules the signed slot with the signed provider | Allowed |
| Availability token is used for appointment creation | Role/privilege denial |
| Agent changes patient, provider, slot, tenant, action, or requested role | TTS or RLS denial |
| Autonomous agent requests a broader profile than provisioned | PDP denial |
| External exporter reads its organization's approved export | Allowed |
| External exporter crosses tenants or queries unapproved relations | RLS/privilege denial |
| Intermediary presents only its workload credential | Database-token issuance denial |
| Invalid token crosses an opaque intermediary | Rejected at the next enforcement boundary |

## 11. Exit criteria

- All four principal paths use the same authority vocabulary and token pipeline.
- No service workload credential alone produces patient-data authority.
- No caller-visible API accepts `db_role` or `db_capability`.
- Transaction Tokens replace principal-token propagation across intermediaries.
- Database tokens are issued only after authoritative action/resource policy.
- PostgreSQL capability roles and RLS enforce actual reads and writes.
- The delegated scheduling demo proves availability-only disclosure and
  race-safe, patient-attributed appointment creation.
- Redacted teaching logs distinguish subject, actor, workloads, action, target,
  and capability without becoming an authorization input.

## 12. Non-goals

- A general-purpose service mesh or semantic authorization sidecar.
- Arbitrary SQL generated by callers or agents.
- A production entitlement-administration console.
- Real provider calendar integrations or notifications.
- Production key management, HA, managed PostgreSQL, or cross-region operation.
