# Database contract

The schema owns services, roles and hierarchy, permissions, role-permission links, service restrictions, scoped principal roles, principal overrides, and superadmin principals. The canonical reference set is defined by RBAC in `internal/domain/model/reference_data.go`: six roles and the `core` service. Principal assignments are environment data.

Migration `002_seed_default_roles_and_principals.up.sql` is a historical seed
for the canonical roles, `core` metadata, and seven fixed principal-role
assignments. Its current contents are frozen; Git history includes an earlier
revision that seeded `manager` for principal `...00a2` before the role changed
to `moderator`. New behavior belongs in a later migration. The regular
`task migrate-up` schema profile deliberately skips 002 and ensures canonical
reference data. `task migrate-up-with-legacy-fixtures` applies 002 only when
its ledger disposition is intentionally excluded; it never replays a recorded
or unresolved seed. The release-review grant for principal `...00b1` is a
separate fixture prerequisite, not evidence that 002 ran.

The seven historical grants are classified as follows: `...00a1` (admin),
`...00a2` (moderator), `...00a3` (teacher), `...00b2`/`...00b3` (student),
and `...00c1` (user) are legacy fixed seeds with no other known consumers in
the inspected repositories. `...00b1` (student) is a release-review fixture:
the Infrastructure release helper requires that exact grant before it
provisions the review identity. This is a release/test prerequisite, not
evidence that any of the seven are production service principals. The fixed
IDs and global scope are migration fingerprints for adoption; the `...00b1`
grant alone never proves 002 history.

Role descriptions and a hierarchy diagram in the old wiki are not themselves enforced policy. Active authorization is determined by stored assignments and the code path that is actually wired.

## Migration execution

`cmd/ms-rbac-migrate` is the single forward migration runner. It reads the
versioned SQL in `migrations/` and records each migration's disposition in
`rbac_schema_migrations`: applied, adopted as applied, manager-era adopted, or
intentionally excluded. `status` reports unresolved 002 history rather than
guessing from absent ledger rows.

For a ledgerless database, `up` adopts only a complete catalog match for
migration 001 and one unambiguous 002 footprint: either no 002 seed markers at
all, a complete current moderator-era seed, or a complete known manager-era
seed with exact fixed IDs, global scopes, and canonical service data. Partial
or conflicting schemas/data stop before the ledger is written. Adoption
preserves unrelated rows. A fresh database must have no non-extension public
schema objects; objects owned by `pgcrypto` are allowed. The 001 schema
validator checks tables, columns, constraints, indexes, enums, and unexpected
public schema objects. Canonical role keys/titles are checked, while role IDs
may be generated; the `core` service must match its stable ID, key, and title.

Migration 001 defines no views, materialized views, or rewrite rules. Adoption
rejects every non-extension `pg_rewrite` row attached to a relation in
`public`, including user rules on tables and the generated `_RETURN` rule for
a public view. Only rules directly owned by `pgcrypto` are exempt; rules owned
by other extensions are rejected. The check also runs when classifying a
database containing only the migration ledger, before any migration-ledger
writes. Rewrite rules attached to relations in `pg_catalog` are outside this
public-schema check.

The schema profile records 002 as intentionally excluded and still applies
later migrations in order. An explicit legacy profile may then apply that
excluded migration. A missing disposition with ambiguous data is unresolved
and fails closed. Canonical reference data is ensured after the base schema
and before later migrations. `status` reports database, role, superuser,
public-table count, and per-migration disposition without reading principal
assignment details.

The runner accepts `DB_DSN`, so it can target the Docker Compose `postgres`
endpoint or the shared native PostgreSQL endpoint without changing migration
files. Rollback keeps the advisory lock, down SQL, and ledger update on one
database session; SQL changes and ledger deletion share a transaction. The
manager-era adoption cannot be rolled back with the current moderator-era 002
down migration and is refused.

The migration integration suite is opt-in. It requires
`RBAC_MIGRATION_TEST_ADMIN_DSN` to point to a loopback disposable PostgreSQL
server's `postgres` database, plus
`RBAC_MIGRATION_TEST_ALLOW_CREATE_DATABASE=YES`; each case creates and drops
its own randomly named test database.

## Disposable HTTP integration fixture

`go run ./cmd/ms-rbac-http-integration` requires the same explicit disposable
server opt-in: `RBAC_MIGRATION_TEST_ADMIN_DSN` and
`RBAC_MIGRATION_TEST_ALLOW_CREATE_DATABASE=YES`. The admin input must be a
PostgreSQL URL naming a loopback host, the `postgres` database, and an explicit
user. Only the `sslmode` URL query parameter is accepted; alternate endpoint
fallbacks must also be loopback. The adapter verifies the connected database
and superuser identity before creating a uniquely named `rbac_http_test_`
database. These inputs must identify an authorized disposable server.

The adapter replaces `DB_DSN` for its children, runs
`go run ./cmd/ms-rbac-migrate up` for the existing schema profile and canonical
roles, then runs `go test -tags=integration ./test/integration -count=1`.
It drops only the exact database whose creation it confirmed, including after
migration/test failure or cancellation. Cleanup uses a separate bounded
connection and a cleanup failure fails the command. An unconfirmed database
creation fails closed without deleting a potentially unowned database.
Missing configuration fails before testing; direct tagged HTTP tests also
fail when `DB_DSN` is missing. Both Testing Policy HTTP logical commands and
the native CI HTTP step invoke this adapter. No NATS or application service
process is needed for these in-process HTTP tests.

The adapter also detects when its original `go run` parent exits, because a
policy timeout can signal that wrapper without forwarding the signal to its
child. Cancellation stops the owned migration/test process group and triggers
the same database cleanup path.
