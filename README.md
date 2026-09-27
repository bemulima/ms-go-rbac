# ms-rbac-service

This repository provides a lightweight RBAC microservice implemented in Go. The service exposes administrative HTTP endpoints for managing services, roles, permissions, and principal assignments. Data is stored in Postgres via the migrations in `migrations/`, which keeps role assignments persistent across restarts.

## Architecture
- `cmd/ms-rbac-service` — composition root: config load, dependency wiring, and HTTP server lifecycle.
- `internal/domain` — entities and domain errors.
- `internal/usecase` — business logic for services, roles, permissions, principals.
- `internal/transport/http` — API, admin, and private HTTP contours.
- `internal/transport/message` — inbound Core NATS RPC handlers.
- `internal/infrastructure/persistence/postgres` — Postgres repository implementations.

## Messaging Boundary
- Retained broker scope for this service is limited to Core NATS RPC: `rbac.assign-role` and `rbac.checkRole`.
- Both subjects are request/reply only and queue-group-safe by design.
- `rbac.assign-role` is a mutating RPC and must remain idempotent for duplicate retries.

## Running locally

```
docker compose up -d
task migrate-up
go run ./cmd/ms-rbac-service
```

The server listens on `HTTP_ADDR` (defaults to `:8080`). The DB connection is configured via `DB_DSN`.

Example `DB_DSN`:
```
postgres://rbac:rbac_password@postgres:5432/rbacdb?sslmode=disable
```

## Example usage

Create a service (admin API is versioned under `/admin/v1`):

```
curl -X SET http://localhost:8080/admin/v1/service \
  -H 'Content-Type: application/json' \
  -d '{"key":"example","title":"Example Service"}'
```

List services:

```
curl http://localhost:8080/admin/v1/service-list
```

## Default roles

RBAC owns the canonical role definitions in `internal/domain/model/reference_data.go`:

- `admin`
- `moderator`
- `teacher`
- `student`
- `user`
- `guest`

`task migrate-up` applies the schema and ensures these roles plus the `core`
service reference. It does not create principal-role assignments. Existing
deployments that explicitly depend on the historical fixed principal grants
can use `task migrate-up-with-legacy-fixtures`; it applies the current 002 seed
only when the migration ledger says it was intentionally excluded. Adoption
recognizes the known earlier manager-era footprint and refuses partial or
ambiguous history instead of replaying the seed.

Only existing roles can be assigned via `PATCH /api/v1/principal-role/update`.
Add new canonical roles through the RBAC-owned reference model and its bootstrap
tests; ordinary principal assignments remain environment data.

## Testing
- Integration-style HTTP contract tests (requires `DB_DSN`): `GOCACHE=../.gocache go test -tags=integration ./test/integration`
- Covers role/permission creation, assignment, permission lookup, and default `user` role assignment helper.

## Native macOS development

The application stays topology-neutral: Docker Compose uses `postgres` and
`nats` DNS names, while the native task supplies loopback endpoints through
environment variables. Follow [the native development guide](docs/native-development.md)
for the supported PostgreSQL, NATS, migration, and process lifecycle.
