# ADR 0008: Signed session context with shared roles and forced RLS

- Status: Accepted and implemented
- Date: 2026-08-06

Phase 2A retains this ADR's shared-role and immutable-`system_user` decision but
generalizes persona-named roles into operation capabilities and replaces
`principal_type` with `principal_kind` plus `access_profile`; see ADR 0009.

## Context

The demo must enforce three multi-tenant access rules at the database boundary:

- an organization administrator may read every patient in their organization;
- a provider may read only patients explicitly assigned to that provider in
  the same organization;
- a patient may read only their own record in the same organization.

Every database action must remain attributable to the originating subject.
Creating a PostgreSQL login role for every application subject would preserve
attribution but add lifecycle overhead unrelated to row authorization.

PostgreSQL 18's OAuth validator callback can return an authenticated identity
(`authn_id`) and PostgreSQL exposes it immutably as `system_user`. Ordinary
`pg_ident.conf` mapping can separately select a bounded SQL role.

## Decision

The TTS derives database access from an authoritative subject directory after
verifying the Transaction Token. A caller cannot provide `org_id`,
`principal_type`, `patient_id`, or `db_role`. The 30-second signed database
token binds those claims to `sub`, `act.sub`, `txn`, audience, scope, and `jti`.

The validator verifies the signature and exact claim profile, independently
derives the role required by `principal_type`, and rejects a connection when
the requested PostgreSQL role differs. It returns this bounded identity:

```text
v1:<org_id>:<principal_type>:<subject>:<patient_id-or-none>
```

PostgreSQL records it as `system_user = oauth:<identity>` and maps it through
ordinary `pg_ident.conf` to one of three shared `LOGIN` roles:

| Principal type | PostgreSQL role |
|---|---|
| `org_admin` | `custody_org_admin` |
| `provider` | `custody_provider` |
| `patient` | `custody_patient` |

The protected tables are owned by a separate `NOLOGIN`, `NOBYPASSRLS` role and
use `ENABLE ROW LEVEL SECURITY` plus `FORCE ROW LEVEL SECURITY`. A restrictive
tenant policy is ANDed with persona-specific policies. Provider access is
joined against `provider_patient_assignments`; patient access compares the
signed patient identifier; administrator access is still tenant-restricted.

The application does not use session variables or `SET LOCAL` for identity.
Each transaction gets a new physical OAuth connection so one subject's
`system_user` cannot leak into another subject's request.

## Consequences

- Application-user provisioning no longer creates or drops PostgreSQL roles.
- Principal context is retained in validator-controlled `system_user`, while
  `current_user` honestly represents a shared authorization class.
- A forged application GUC cannot alter RLS context.
- The validator and TTS directory are authorization-critical trust anchors;
  both enforce the principal-to-role mapping independently.
- Per-transaction connection establishment remains a deliberate cost.
- A production directory needs revocation, versioning, cache bounds, and a
  durable provider-assignment administration workflow.
