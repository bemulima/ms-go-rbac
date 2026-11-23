# CAT-02D2B1A — exact default-scope Student role check

**DRAFT / SOURCE_ONLY / NOT_RUNTIME_VERIFIED.** This is a new narrow RBAC
NATS request/reply operation for Codechuman's unified Practice catalog. It
does not replace or change existing `rbac.checkRole` or its consumers.

## Contract

| Item | Exact value |
| --- | --- |
| NATS subject | `rbac.checkDefaultStudentRole` |
| Queue | `ms-go-rbac` |
| Request | `{"user_id":"<canonical nonzero UUID>"}` (exactly one property) |
| Allowed response | `{"ok":true,"role":"student"}` or `{"ok":true,"role":"student_pro"}` |
| Denied response | `{"ok":false}` |
| Invalid request | `{"ok":false,"error":"invalid_payload"}` |
| Failed DB/ambiguous default scope | `{"ok":false,"error":"role_check_unavailable"}` |

- The request cannot choose a role, tenant, service, scope or resource.
- `PrincipalRoleRepository.GetDefaultRole` is already implemented and tested
  against the **exact** global tuple of `(tenant_id, service_id,
  resource_kind, resource_id)`. It rejects multiple rows at that scope.
  This endpoint calls **only** that method, never legacy `Get`/`GetByRole`
  (which fall back to an arbitrary scope).
- Only `student` or `student_pro` at the canonical global default scope
  produces a positive decision. An Admin/Guest or foreign-scoped-only Student
  grant receives `ok:false` without exposing the actual role.
- Input is bounded and rejects duplicate, unknown and noncanonical values.
  Backend errors are sanitized; no SQL, scope or identity details leak.
- This NATS subject is **internal**, not a public API. Existing NATS handlers
  do not have a message-level authorization proof. Operators must restrict
  the broker and its subject permissions to trusted service accounts before
  enabling an external Practice catalog route.

## Acceptance still required

1. Run Go unit/vet/policy and existing `GetDefaultRole` PG source/integration
   tests; verify default Student/Student Pro, no default role, foreign scoped
   role, ambiguous default binding and PostgreSQL error.
2. Test a real `rbac.checkDefaultStudentRole` NATS request/reply with the
   actual RBAC database and private broker account; validate queue health,
   timeout, and subject ACLs (including denial from an untrusted account).
3. Wire Practice to this new subject only after RBAC deployment, using the
   Auth-verified subject from `auth.verifyJWT`. Retire the old generic role
   fallback in the new catalog adapter; never change legacy callers.
4. Perform the full Gateway/Practice/PG positive/negative authorization
   matrix before enabling the public GET. No schema migration is required
   for the new RBAC role check.

**No migrations, shared runtime or main merge are performed by this Draft.**
