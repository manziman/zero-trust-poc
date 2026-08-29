# ADR 0003: Boolean AuthZEN decisions with requestable denials

- Status: Accepted
- Date: 2026-08-05
- Stable baseline: AuthZEN Authorization API 1.0 Final
- Experimental baseline: Access Request and Approval Profile Draft 1

## Context

Custody's domain needs four outcomes: allow, deny, require approval, and require
two-party approval. AuthZEN Authorization API 1.0 defines a boolean decision,
so placing those four values directly on its wire format would not conform.

The July 2026 Access Request and Approval Profile defines a requestable denial,
durable task handle, callback or polling completion, and fresh evaluation after
approval. It matches Custody's agent-friendly park-and-resume flow closely.

## Decision

- Map allow to `decision: true`.
- Map hard deny to `decision: false` without `context.access_request`.
- Map both approval outcomes to `decision: false` with
  `context.access_request`.
- Enforce two-party separation as Access Request Service workflow policy.
- Persist approval state in the Access Request Service and only execution
  resumption state in the gateway.
- After approval, perform a fresh PDP evaluation. Approval evidence alone
  never authorizes execution.
- Use `txn` as `X-Request-ID` for project correlation without claiming that
  convention is normative AuthZEN behavior.

## Consequences

- An AuthZEN implementation unaware of the draft approval profile fails closed.
- The PDP remains stateless and authoritative at execution time.
- The draft profile is adapter-isolated and backed by versioned fixtures so it
  can change without spreading experimental shapes through the codebase.
- Callback authentication, task-handle confidentiality, binding integrity,
  idempotency, expiry, and approval replay require explicit Phase 2 tests.
