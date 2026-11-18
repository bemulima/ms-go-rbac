# CAT-49 disposable Reviewer RBAC grant (SOURCE_ONLY)

No privileged role or principal is created by this change. Migration 005
adds one immutable receipt table; it is NOT applied to a shared database.
The existing canonical ms-rbac-operator-bootstrap and its lw_rbac guards remain
unchanged.

The proposed CAT-49 operator-only usecase accepts an Auth registration proof
that is HMAC-bound to run/request/principal/DB, then checks one strict fresh
unprivileged principal, grants ONLY moderator in the default scope, and
records a unique immutable grant receipt atomically in the same transaction.
The DB transaction shares the signup principal lock, rejects a second reviewer
in the same run, role drift, replay changes and takeover of existing Student.

The source is an owner primitive, NOT an executable: it is never wired to
HTTP/NATS/server/CLI. A dedicated independently accepted CAT-49 operator
entrypoint, Auth owner signer, actual DB marker verification and key custody
remain required before any future use. Do not use the rejected V1 STUDENT
fixture or repoint the canonical lw_rbac operator CLI.

Security approval and real disposable PostgreSQL tests are NOT_RUN.
