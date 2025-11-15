# ms-rbac-service

This repository provides a lightweight prototype of an RBAC microservice implemented in Go. The current implementation focuses on administrative HTTP endpoints for managing services, roles, and permissions. Data is stored in-memory, which keeps the prototype simple while allowing the high-level API shape to be exercised.

## Running locally

```
go run ./cmd/ms-rbac-service
```

The server listens on `HTTP_ADDR` (defaults to `:8080`).

## Example usage

Create a service:

```
curl -X SET http://localhost:8080/admin/service \
  -H 'Content-Type: application/json' \
  -d '{"key":"example","title":"Example Service"}'
```

List services:

```
curl http://localhost:8080/admin/service-list
```
