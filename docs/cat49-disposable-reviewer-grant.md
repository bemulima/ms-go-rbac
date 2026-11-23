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

The source is an owner primitive exposed only to the separate, default-OFF
`cmd/ms-rbac-cat49-reviewer` CLI, never to HTTP/NATS/server. An independent
positive security/operator approval of the exact CLI and Auth owner signer,
actual disposable DB identity, signed owner marker and private key custody
are still required BEFORE any execution. Do not use the rejected V1 STUDENT
fixture or repoint the canonical lw_rbac operator CLI.

Security approval and real disposable PostgreSQL tests are NOT_RUN.

## Persistence qualification added in CAT-49

`internal/infrastructure/persistence/postgres/cat49_reviewer_grant_test.go`
exercises the **production repository transaction method**, with an in-memory
`pgx.Tx` fake. It covers exact idempotent replay, changed proof/operator/
principal/request/run conflicts, pre-existing role denial, current role drift,
transaction rollback after receipt failure, and missing-schema fail-closed.
Run the registered `cat49-reviewer-persistence-source` command; no DB required.

`cat49_reviewer_grant_integration_test.go` is build-tagged `integration`.
It exercises actual PostgreSQL transaction atomicity, 8-way exact replay,
immutable receipt triggers, conflicting replays, and role drift. It is
**NOT_RUN** until separately approved task-owned SQL acceptance. It never
executes the Reviewer CLI, creates an Auth identity/session, or qualifies the
independent operator security gate.

The registered `cat49-reviewer-persistence-postgres` command requires:
- `RBAC_CAT49_SQL_APPROVAL=approved-disposable-test-only`, set only after
  explicit approval of a newly created disposable-only SQL acceptance stand;
- `RBAC_CAT49_SQL_OWNER_MARKER_FILE` pointing to a regular private
  permission-0600 JSON owner marker with schema `cat49-disposable-ownership.v1`,
  purpose `cat49-reviewer`, exact run/project/network, RBAC database/user,
  loopback host/port, and optional explicitly attested `postgres_server_ip`;
- `RBAC_CAT49_SQL_DATABASE_URL` matching that marker, for a fresh dedicated
  `cat49_*_test` DB, migration 005 present and immutable trigger installed.

The test independently checks connected DB/user/server identity, denies
superuser/shared/cross-run access, and requires a fresh run with no existing
CAT49 receipt. The test intentionally writes only synthetic RBAC assignments
and immutable receipts inside that one approved disposable database. It is
not safe to rerun on a consumed run without a fresh authorized database.
An opt-in test that SKIPs due to absent approval is **PG_NOT_RUN**, not PASS.

Security Issue #57 remains open: source and PostgreSQL acceptance do **not**
authorize registration, role grant, operator CLI, business publication,
activation, merge, CI waiver, or canonical migrations.
