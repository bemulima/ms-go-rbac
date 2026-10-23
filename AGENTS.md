# Repository Guidelines

## Agent bootstrap

Read .ai/rules/common.md, .ai/service.yaml, docs/README.md, and every affected contract before changing files. Code, migrations, tests, and repository-owned docs are authoritative; the former central wiki is historical input only.

## Architecture invariants

- internal/domain owns RBAC/PDP models; internal/usecase owns CRUD and principal role/permission behavior; adapters own HTTP, NATS, PostgreSQL, PDP storage, and cache; internal/app wires active behavior.
- ms-go-rbac owns role, permission, assignment, scope, override, and superadmin data.
- rbac.assign-role and rbac.checkRole are Core NATS request/reply subjects and must remain queue-group safe.
- Do not describe the PDP as active until it is wired into bootstrap and its repository interface matches the PostgreSQL adapter.
- HTTP mutations are denied at the owner router; do not reopen them using actor headers. Reads remain legacy read-only. Service/role/permission handlers retain their SET-vs-POST defect behind that denial; do not broaden this patch. Administrative bootstrap is operator CLI only.

## Verification and delivery

- Use .ai/commands.yaml; run policy, tracked-file gofmt, go vet ./..., and go test ./....
- Database and authorization changes require migration, producer/consumer, denial-path, and privilege-escalation review.
- Do not run migrations, services, GitHub publication, or deployment without required authorization.
