# Versioned contract fixtures

These synthetic JSON documents pin the standards profile selected for Custody:

- Transaction Tokens draft 11;
- AuthZEN Authorization API 1.0 Final;
- AuthZEN Access Request and Approval Profile Draft 1;
- Custody's separate PostgreSQL access-token profile, including derived
  multi-tenant persona and role claims.

They are examples for review and future conformance tests. Encoded strings are
placeholders, not valid or reusable credentials. Updating a pinned standard
requires updating the relevant ADR and fixtures in the same change.

The JSON Schemas for database access tokens and PostgreSQL validator events,
together with the Go/C negative tests, make type, audience, identity, and
authorization-format drift visible during review.
