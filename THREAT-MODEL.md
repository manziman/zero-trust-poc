# Phase 2A threat model

## Security claim

Custody demonstrates that a human, delegated human, autonomous agent, or
external machine can exercise narrow, attributable data authority through
intermediary workloads that have no standing patient-data permission. The
database independently limits both the operation and rows using a short-lived
signed credential.

It does not claim that Docker Compose, local HTTP, development secrets, or the
POC key lifecycle are production controls.

## Assets and trust anchors

Protected assets include Keycloak credentials, TTS signing keys,
Transaction Tokens, database tokens, patient records, private calendars,
appointments, PostgreSQL mappings/policies, and published database public-key
state.

Explicit trust anchors are Keycloak and its realm/JWKS; the Transaction and
database token issuers; the authoritative policy catalog; the gateway route
decision; the database-token endpoint; PostgreSQL, its C validator, schema, and
RLS policies. Compose networks express topology only.

## Boundary controls

| Threat | Phase 2A control |
|---|---|
| Human login interception or CSRF | Authorization Code, S256 PKCE, exact loopback redirect, state, nonce, bounded callback, in-memory tokens |
| Workload impersonation | Distinct confidential clients; issuer, audience, signature, expiry, client ID, and narrow-scope checks |
| Approved workload replays another workload's transaction | Gateway requires the authenticated client ID to equal signed `req_wl` |
| Workload credential used as data authority | Database-token issuance requires a valid Transaction Token; PostgreSQL accepts only database-audience tokens for bounded operation roles |
| Principal/access/database token substitution | Different types, issuers, audiences, keys, claims, header uses, and maximum lifetimes |
| Header smuggling | Exactly one `Authorization` and `Txn-Token` value accepted at security boundaries |
| Transaction replay | Receiver-local caches consume each `txn` once until token expiry |
| Caller selects tenant/profile/role | TTS rejects `org_id`, `access_profile`, `db_capability`, and `db_role`; authoritative context is catalog-derived |
| Action or resource substitution | Gateway matches method/path to signed action/resource; database-token role is an exact private action mapping |
| Availability token creates appointment | Different action and database role; gateway route rejection; scheduling role lacks read/write table privileges beyond its function |
| Provider private-calendar disclosure | Private calendar has no runtime grants; availability role sees only a safe bookable-slot relation |
| Appointment patient/provider/slot tampering | Narrow function derives security-sensitive values from immutable `system_user`; signed resource, tenant checks, uniqueness, and forced RLS apply |
| Cross-tenant read/write | Signed `org_id`; restrictive tenant policy combined with access-profile RLS |
| Provider reads unassigned patient | `provider_assigned` policy joins signed provider identity to forced-RLS assignments |
| Patient reads another patient | Signed patient ID plus `patient_self` policy |
| Autonomous agent self-escalation | Catalog fixes its kind/profile/tenant/actions; caller cannot request a broader profile or role |
| External exporter crosses tenant or uses normal reader | Separate external-machine profile, export action/role, tenant RLS, exact role/action validation |
| Database auth downgrade | pgx `RequireAuth="oauth"`; OAuth-only HBA mappings; malformed credentials fail closed |
| Validator key compromise or stale state | Private key remains with TTS; public key is atomically published before PostgreSQL starts; offline Ed25519 verification |
| Role/claim confusion | Go issuer and C validator require exact action-to-role mapping and requested PostgreSQL username consistency |
| RLS bypass | `NOLOGIN` object owner, forced RLS, non-superuser `NOBYPASSRLS` runtime roles |
| Session-context spoofing | Policies parse immutable `system_user`; no application GUC or `SET LOCAL` authority |
| Sensitive SQL/token logging | Parameterized/fixed queries and redacted operational logs; no tokens, patient rows, or bind values |

No bearer credential, compact token, client secret, password, patient row, or
bind value is written to operational logs. The validator logs only a digest of
`jti`.

## Trust intentionally retained

The TTS and its catalog can issue authority, the database-token issuer can map
that authority to capabilities, and PostgreSQL can enforce or bypass its own
schema policy. A compromise of those components or their signing keys is not
solved by adding more tokens. Custody makes these trust anchors explicit; it
does not make them untrusted.

The resource service is trusted for availability and response integrity, but
not for row authorization. It can drop a request, return fewer rows, or corrupt
a response. It cannot use its workload credential alone to obtain patient-data
authority, and its SQL session is still capability/RLS limited.

## Known residual risks

- The in-process policy catalog is deterministic fixture code, not a separately
  operated AuthZEN PDP. The database-token endpoint independently validates the
  signed Transaction Token, but Phase 2B should bind issuance to a durable policy
  decision identifier when authorization moves out of process.
- Approval and step-up flows are not implemented. Sensitive operations needing
  human approval must not be added until requestable denial, independent approval,
  and fresh evaluation are present.
- Replay caches are process-local and reset on restart. They are appropriate for
  the single-instance POC, not clustered deployment.
- PostgreSQL checks a database token's unique `jti` and 30-second window but has
  no cross-backend consumed-token store. A stolen token can be replayed during
  that window; production requires channel/token binding or shared one-time use.
- The demo uses local HTTP and static development secrets. A process controlling
  the host/container can observe credentials.
- Key rotation overlap and active revocation are not implemented. Short TTL is a
  mitigation, not revocation or continuous access evaluation.
- Shared database roles represent operations, not people. Queries reporting only
  `current_user` lose principal context; database policy therefore parses the
  validator-controlled `system_user` instead.
- The fixture entitlement catalog needs a durable source, assignment lifecycle,
  revocation semantics, bounded caches, and controlled administrative changes.
- RLS is not a universal confidentiality proof. Referential-integrity and
  uniqueness checks can reveal existence; schema/query changes need dedicated
  database-security review.
- Per-principal physical connections preserve immutable `system_user` but add
  connection cost and complicate conventional pooling.
- The custom PostgreSQL server validator requires self-managed PostgreSQL.
  Managed services that cannot load it need a different enforcement design.
- Keycloak, TTS, PostgreSQL, and their keys are single points of failure.
  HA, HSM/KMS integration, backup, disaster recovery, and formal verification are
  out of scope.

## What this does not solve

Custody cannot prevent a legitimately authorized principal from misusing data
they are allowed to receive. It does not secure compromised endpoints, prove
policy correctness, classify data, eliminate inference channels, provide consent
management, or make an external integration trustworthy after export. It reduces
ambient service authority and enforces explicit transaction authority at the
database boundary; it is not a complete healthcare security program.
