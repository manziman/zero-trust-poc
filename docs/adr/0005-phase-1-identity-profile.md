# ADR 0005: Separate human and workload identity flows

- Status: Accepted
- Date: 2026-08-05

## Context

The demonstration needs an attributable initiating principal and independently
authenticated workloads. A password grant or a shared internal bearer token
would erase that distinction.

## Decision

- Humans use Keycloak Authorization Code flow with a public `custody-cli`
  client, an exact loopback redirect, mandatory S256 PKCE, state, and nonce.
- The imported realm explicitly attaches a minimal `custody-subject` scope to
  `custody-cli`; its Subject mapper is required because this deliberately
  minimal realm does not import Keycloak's built-in `basic` client scope.
- Workloads use distinct confidential clients and service accounts with no
  browser, implicit, password, or Direct Access Grant flows.
- The immutable Keycloak user `sub` identifies a human. Headless paths use
  stable, explicitly non-human client IDs (`automation-principal` and the
  three `demo-*` personas) instead of realm-generated service-account UUIDs.
- Every service validates issuer, audience, signature, expiry, key ID, and
  caller identity. Compose network membership is not authorization.

## Consequences

The interactive demo requires a browser. CI remains deterministic without
automating a login form or storing a human password in a workflow. Local realm
secrets are fixtures only and must never be reused.
