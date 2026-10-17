# C2-B isolated MENTOR provisioning counterpart

Status: OWNER_AGREED_IMPLEMENTATION_ONLY; INDEPENDENT_REVIEW_PENDING. Explicit agreement received in task chat. Canonical cross-owner proposal: `ms-go-auth/docs/c2-b-isolated-mentor-bootstrap-contract.md`.

RBAC owns a closed verification-only CLI, fixed test-environment/DB/marker/identity mapping and dedicated Auth fixture signature verification, followed by transactional assignment + immutable receipt. Only the exact isolated mentor and learner-negative-probe entries are permitted. No role/scope chosen by public callers, existing student promotion, ADMIN provisioning or production seed/grant change. Role `mentor` is created only in the approved isolated DB; canonical production roles stay unchanged. Existing principal lookup/checkRole remain the readback boundary. Existing HTTP MutationAdmission and student-only signed signup RPC are unchanged.

Add only owner-controlled audit storage/migration for isolated proof. Environment/proof validation precedes receipt reads/writes; exact replay is stable, changed binding/conflicting role denied. Auth confirms the role and only then finalizes credentials and ordinary signin. Independent review before publication is required.

Separate existing policy failure: obsolete-reference scan currently matches only generated `.ai/testing/policy/policy-runner.cjs` (80 bundled diagnostic/policy strings), not owned rules/docs. Proposed minimal script correction excludes only that exact generated bundle from prose-reference scanning, leaves the bundle/lock and every existing human rule byte-identical, and adds regressions proving that AGENTS/docs/.ai rule references still fail while bundled test strings do not. No deletion of rules, disabled check or change to role admission.

Implementation entrypoints: Auth `go run ./cmd/ms-go-auth-c2b-fixture prepare mentor|learner` and `finalize mentor|learner <private-rbac-receipt-file>` (password on stdin); RBAC `go run ./cmd/ms-rbac-c2b-fixture apply` (signed intent on stdin). Enablement: `C2B_FIXTURE_ENABLED=true`, `C2B_ENV=c2b-proof`, owner APP_ENV=c2b-proof, `C2B_OWNERSHIP_MARKER`, exact `C2B_FIXTURE_DSN`, and Auth-only `C2B_AUTH_SIGNING_KEY`. Marker expires within 24h, fixes key/run/DB/execution; files must be private regular files. New migration Auth0006 / RBAC004 stores immutable receipts, rejects update/delete/truncate and nonempty rollback. Auth runtime additionally requires `AUTH_C2B_PROOF_ENABLED=true`, loopback `c2b_auth_runtime`/exact DB, migrations disabled and valid marker; audited mentor role lookup rejects expired authority on token issuance. No fixture key in Auth runtime, no JWT key in bootstrap. Runtime credentials cannot insert bootstrap audit or assign roles.

Least-privilege live characterization: SELECT FOR KEY SHARE on role required UPDATE privilege; the new bootstrap's unnecessary row lock was removed, keeping its fixture principal INSERT/SELECT-only. FK plus assignment/audit transaction preserves binding. No broader database grants were introduced to make the proof pass.

## R1 effective PostgreSQL configuration gate

The retained isolated destination is exactly `127.0.0.1:49920`; database and
principal remain the fixed owner allowlist above. Require a literal `postgres`
URL with an explicit nonempty password and exactly `sslmode=disable` as the
query. Reject extra/duplicate/encoded query parameters, encoded identity/path,
other hosts/ports, multi-host fallback, service files and any present `PG*`
environment variable (including an empty one). Password escaping is supported;
passwords and driver parse errors are never included in gate errors.

`PrepareConnection` validates the marker/environment and parses with the actual
pgx driver before any database opener runs. It checks effective host, port,
user, database, TLS, runtime options and fallback destinations. The CLI uses
that parsed configuration object: Auth passes pgx stdlib's SQL pool to GORM
through `postgres.Config.Conn`; RBAC passes the validated pool configuration
to `pgxpool.NewWithConfig`. Neither CLI reconnects using the raw DSN. Auth proof runtime likewise passes
the validated runtime-principal configuration to pgx stdlib/GORM; production
connection setup is unchanged.

Regressions cover the original host override, endpoint/identity/options/service
overrides, duplicates/encoding, PG environment, wrong destination and production.
CLI opener spies prove zero connection attempts on denial. An in-memory
PostgreSQL protocol fixture exercises the real positive GORM/pgxpool connection
and checks the fixed startup user/database without touching preserved stores.
This remediation still requires separate independent review before publication.
