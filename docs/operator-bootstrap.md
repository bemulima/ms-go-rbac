# Operator-only initial administrative grant

HTTP role/permission mutations are retired and return403, even for a valid ADMIN. The only newly supported administrative grant capability is cmd/ms-rbac-operator-bootstrap; it is not wired to the server, startup, HTTP or NATS. Existing signed Auth signup still creates only STUDENT.

The authority is explicit local operator execution with custody of the existing database credential, not client-provided role headers. These environment guards are misconfiguration protection, not remote authentication. Use a restricted local operator shell; never expose this executable through a web handler, shell service or container execution API.

## Preconditions

After separately approved migration004, use an exact principal already registered through Auth with current default role student. No user is created here. Role and request ID have no defaults. Existing moderator/admin assignments cannot be overwritten or adopted without a stored matching receipt. The existing E2E MODERATOR and original STUDENT are left untouched.

Required environment: APP_ENV=local-operator, RBAC_OPERATOR_BOOTSTRAP=enabled, RBAC_OPERATOR_ENVIRONMENT=learning-workspace-local, DB_DSN supplied privately. CLI requires --database lw_rbac, --database-user matching the actual non-superuser database login. Only localhost/127.0.0.1/platform-postgres:5432 connections are admitted, with server-side database/user checks. No credential is accepted in arguments or printed. Missing schema/authority or any guard failure denies the command.

Example invocation shape (not executed; replace placeholders only after exact owner approval):

```sh
APP_ENV=local-operator RBAC_OPERATOR_BOOTSTRAP=enabled \
RBAC_OPERATOR_ENVIRONMENT=learning-workspace-local \
./ms-rbac-operator-bootstrap \
  --database lw_rbac --database-user lw_rbac \
  --principal-id <registered-student-uuid> --expected-role student \
  --role moderator --request-id <operation-uuid> --operator <local-operator-name>
```

ADMIN is possible only with explicit --role admin and the same operator guards, never automatically. MODERATOR has no network role-management authority. This is a bounded initial bootstrap, not a general role editing API.

PrincipalRoleUsecase validates exact intent; its repository serializes grants, checks expected role under row lock, reuses the assignment persistence helper and commits an immutable database receipt in the same transaction. Exact request replay returns identical receipt only while the grant still matches. Changed intent, another request for the same principal, unexpected current role or drift fails without partial grant. JSON stdout is the verifiable audit receipt; errors are static and contain no DSN/proof. Preserve receipts and separately audit operator access.

## Rollout / rollback

Source tests do not protect the running runtime. Build reviewed RBAC/Gateway artifacts without activating them, separately approve and apply additive004, then approve targeted service rollout preserving28-container topology and volumes. Owner must decide rollout order/temporary containment of the currently EXPOSED old runtime. Regenerate Gateway deployment templates from the patched owner source; do not silently overwrite Infrastructure's local email-code routing customization.

Verify guest/Student denial via edge and direct RBAC, legacy/admin aliases, forged headers, preserved role reads and signed student provisioning. Confirm exact original Student and E2E MODERATOR roles without modifying them. Bootstrap acceptance must use an explicitly authorized independent test principal and retain its receipt.

Do not roll back to the vulnerable public mutation surface. Retain fail-closed Gateway containment on any application rollback. Migration004 down refuses a populated receipt table; no role reversal or receipt deletion is automatic. Recover application availability using a reviewed secure prior image/patch while retaining additive schema. No rollback/activation/migration was performed in source work.

## Source verification and deferred PostgreSQL acceptance

`go test ./...` covers direct HTTP denial, CLI guards and transaction protocol harnesses. `go vet ./...` and policy/format checks are required. `env -u RBAC_SIGNUP_TEST_DATABASE_URL go test -tags=integration ./internal/infrastructure/persistence/postgres -run '^TestOperatorBootstrapSQLConcurrentReceiptAndDrift$' -v` compiles the real PostgreSQL test and proves its no-database skip guard; it is NOT database acceptance. Real execution requires separately approved, already migrated owned loopback *_test DB and migration004, never canonical lw_rbac. The test creates no database or server. Future actual PostgreSQL receipt/concurrency/rollback/trigger validation remains a pre-activation acceptance gate; no canonical privileges are exercised by source tests.
