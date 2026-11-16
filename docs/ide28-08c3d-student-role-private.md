# IDE28-08C3D — RBAC exact student role private owner read

This is a **default-OFF Draft source slice**, not deployment approval.

- `RBAC_IDE_STUDENT_ROLE_ENABLED=false` by default.
- Dedicated `RBAC_IDE_STUDENT_ROLE_TOKEN` required only when enabled (32–4096 printable non-placeholder bytes).
- New read-only `GET /private/ide/v1/principals/{studentID}/student-role`.
- Requests must have exactly one dedicated token header and `X-Service-Name: ms-go-practice-runtime`. Browser bearer/cookies, caller role headers, duplicates, query/body are rejected before repository access.
- RBAC reads **only the canonical default scope** through `PrincipalRoleRepository.GetDefaultRole`; never call the legacy `Get` fallback, which could select a foreign scope.
- Only `student`/`student_pro` are mapped to `STUDENT`/`STUDENT_PRO`. Every other role, missing role or ambiguous role fails closed.
- Emits only `rbac-ide-student-role.v1`, exact student ID and role, with `Cache-Control: private, no-store`.
- This endpoint proves RBAC's current default role to an authenticated Runtime *service*. Runtime must separately authenticate its caller and verify persisted TaskInstance and CURRENT Student eligibility.

Tests were committed first. Source qualification on Mac Go 1.24.4:

```bash
go test ./internal/transport/http/private -run '^TestIDEStudentRolePrivateRead' -count=1 -v
go test ./internal/config -run '^TestIDEStudentRoleRead' -count=1 -v
go test ./internal/transport/http/... ./internal/config/... -count=1
go vet ./internal/transport/http/... ./internal/config/...
go build ./...
```

Go, Postgres, live HTTP, cross-service credentials and Auth/RBAC E2E are NOT_RUN in the cloud executor. The feature must remain disabled until a separate integration gate. No shared DB/containers, CAT, Epic #32 or ZX10 worktree changes.
