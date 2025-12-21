# ms-rbac-service

This repository provides a lightweight RBAC microservice implemented in Go. The service exposes administrative HTTP endpoints for managing services, roles, permissions, and principal assignments. Data is stored in Postgres via the migrations in `migrations/`, which keeps role assignments persistent across restarts.

## Architecture
- `cmd/ms-rbac-service` — entrypoint that boots the HTTP server.
- `internal/app` — wiring: config load, use case creation, HTTP server setup.
- `internal/domain` — entities and domain errors.
- `internal/usecase` — business logic for services, roles, permissions, principals.
- `internal/adapters/http` — net/http handlers and routing.
- `internal/adapters/postgres` — Postgres repository layer.

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

Default roles are seeded via migrations:

- `admin`
- `moderator`
- `teacher`
- `student`
- `user`
- `guest`

Only existing roles can be assigned via `POST /assign_role`. Add new roles through the `/admin/role` endpoint if needed, then run migrations for seeds.

## Testing
- Integration-style HTTP contract tests (requires `DB_DSN`): `GOCACHE=../.gocache go test ./...`
- Covers role/permission creation, assignment, permission lookup, and default `user` role assignment helper.
