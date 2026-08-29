# ADR 0001: Go services and a C PostgreSQL validator

- Status: Accepted
- Date: 2026-08-05

## Context

Custody contains several small network services and one PostgreSQL server
module. The services benefit from one readable language, straightforward
concurrency, and small container images. The validator must implement
PostgreSQL 18's C ABI, obey PostgreSQL memory-allocation rules, and expose
`_PG_oauth_validator_module_init`.

## Decision

Use one Go 1.26 module for the TTS, gateway, resource service, CLI, and shared
internal packages. Use C and PGXS for the PostgreSQL OAuth validator.

Use pgx v5.10 or newer for the resource-service database client because its
`OAuthTokenProvider` supplies an already-minted bearer token without cgo.

## Consequences

- Service code and tests use one toolchain and can build as static binaries.
- The validator has the smallest possible interoperability surface with
  PostgreSQL.
- C code is deliberately kept narrow and receives disproportionate negative
  testing because it executes inside the database server.
- Rust remains a future option only if its exported callback ABI, allocation,
  lifetime, and panic-containment behavior are proven. Custody will not carry
  parallel C and Rust validators.
