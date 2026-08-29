# ADR 0009: Transaction boundaries and authorization-owned capabilities

- Status: Accepted and implemented for Phase 2A
- Date: 2026-08-06

## Context

Custody must support direct users, users acting through agents, autonomous
internal agents, and external machine clients. The interesting paths include
intermediary workloads between the authority-bearing principal and PostgreSQL.

A principal access token could be exchanged directly for a database token.
Doing so in a multi-hop workflow would require either propagating the
principal's general-purpose token through every intermediary or issuing a
database credential before it is needed. A semantic sidecar could hide the
exchange mechanics, but it would need route- and payload-specific business
configuration and become another authorization-critical process.

Requiring callers to know database roles would also couple public APIs to the
current PostgreSQL privilege implementation and allow callers to propose their
own privilege level.

## Decision

1. Mint a Transaction Token at the first intermediary boundary. It binds the
   principal, optional delegated actor, action, resource constraints, tenant
   context, and transaction identifier.
2. Forward the exact Transaction Token through the call chain and issue the
   short-lived PostgreSQL token only at the last responsible moment.
   The gateway binds the authenticated calling workload to signed `req_wl` so
   one approved workload cannot replay another workload's authority.
3. A component validates a Transaction Token when it trusts claims, makes an
   authorization decision, issues another capability, or performs a
   non-database side effect. A database-only intermediary may carry the token
   opaquely.
4. Callers request business actions and resources. They never request
   `db_capability`, `db_role`, tenant, or access-profile claims.
5. The PDP authorizes business intent. The TTS privately maps the allow
   decision to a bounded database capability and returns the required
   `database_user` with the database token.
6. PostgreSQL independently validates that database token and enforces the
   capability against actual SQL using grants, column/relation boundaries,
   RLS, write checks, and integrity constraints.
7. Do not add a semantic authorization sidecar in Phase 2. First implement an
   explicit Go integration; then evaluate generated gRPC interceptors for
   token mechanics and typed action/resource extraction. Generated clients
   must not contain database-role mappings.

## Consequences

- Principal tokens do not traverse the internal service chain.
- Database credentials are not exposed before database access is imminent.
- Application services have no standing data identity and cannot select their
  own privilege level.
- Database-only services can remain thin and need not duplicate JOSE
  verification merely to forward an opaque artifact.
- Services performing queue, email, external API, or other non-database effects
  still need a validating enforcement boundary before acting.
- The TTS/PDP catalog and PostgreSQL policies must be contract-tested so an
  action cannot map to a broader capability than intended.
- gRPC generation may reduce integration work, but semantic resource metadata
  remains owned by the API producer and policy remains owned by the PDP/TTS.
