# ms-rbac-service

This repository provides a lightweight prototype of an RBAC microservice implemented in Go. The current implementation focuses on administrative HTTP endpoints for managing services, roles, and permissions. Data is stored in-memory, which keeps the prototype simple while allowing the high-level API shape to be exercised.

## Architecture
- `cmd/ms-rbac-service` — entrypoint that boots the HTTP server.
- `internal/app` — wiring: config load, use case creation, HTTP server setup.
- `internal/domain` — entities and domain errors.
- `internal/usecase` — business logic for services, roles, permissions, principals.
- `internal/adapters/http` — net/http handlers and routing.
- `internal/adapters/postgres` — repository layer (currently in-memory structs; swap here for a DB).

## Running locally

```
go run ./cmd/ms-rbac-service
```

The server listens on `HTTP_ADDR` (defaults to `:8080`).

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

The service starts with a predefined set of roles:

- `admin`
- `moderator`
- `teacher`
- `student`
- `user`
- `guest`

Only existing roles can be assigned via `POST /assign_role`. Add new roles through the `/admin/role` endpoint if needed.

## Testing
- Integration-style HTTP contract tests (in-memory repo): `GOCACHE=../.gocache go test ./...`
- Covers role/permission creation, assignment, permission lookup, and default `user` role assignment helper.
