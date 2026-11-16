# Atomic Mentor role owner (source only)

Parent: `bemulima/learning-platform-business#27`, MENT-01A.
This is the RBAC-owned internal mutation/store contract. It is **disabled by
default**. The separate [executable opt-in](mentor-owner-runtime.md) can mount
its existing consumer; source publication executes no migration or live grant.
The additive [mutation RPC contract](../.ai/contracts/mentor-role-mutation-rpc-v1.md)
now exposes a strict source-only handler for `rbac.applyMentorRole.v1`; it does
not register a listener and its ACK is not current-role authority.

Auth remains the canonical owner of
`ms-go-auth/.ai/contracts/mentor-role-decision-v1.{md,json}`.
The assertion format is unchanged and is not copied into this repository.
Mentor remains the application/decision owner. The existing
[read-only Admin confirmation](mentor-admin-lookup.md) is not mutation-time
authority; the store repeats the exact current Admin check in its transaction.

## Internal entry point and authority

```go
usecase.NewMentorRoleMutation(verifier, store).Apply(ctx, rawProof)
// store: domain.MentorRoleMutationStore
// concrete adapter: repo.NewMentorRoleStore(pool)
```

The use case verifies the exact compact Auth role proof before any store call,
including replay. It pins the SHA-256 of the original bytes and complete
verified value, then supplies a synchronous per-invocation revalidator.
The store invokes it before Begin, after lock acquisition and immediately
before commit initiation, comparing every proof field again. It must use the
local dedicated RSA verifier, not make network owner calls while holding locks.
`ValidMentorRoleProofShape` is only a structural validator; constructing a
Go value or supplying an invented callback is not an authenticated endpoint.
Neither the callback nor raw proof is retained, logged or persisted.

Nil/cancelled context, missing dependencies, malformed/expired/changed proof
and unavailable authority fail closed. A known non-Admin returns
`ErrMentorRoleForbidden`; ambiguous canonical roles or database failure are
unavailable, not a false successful or signed negative result. Error returns
carry a zero result and sanitized categories, not SQL/credential diagnostics.
Only exact known error sentinels receive semantic categories; wrapped or mixed
failures remain unavailable rather than impersonating a known denial. The
mutation RPC adds no authorization bypass and does not change the atomic store.

## Transaction boundary

The pgx adapter explicitly begins READ COMMITTED / READ WRITE, with a bounded
five-second store invocation context (an earlier caller deadline still wins).
Local lock and statement timeouts bound contention. It obtains locks in this
order, at the strongest mode it needs, before reading owner/authority data:

1. `role`, `service`, `service_role`, `mentor_role_scope`: SHARE.
2. `principal_role`, `mentor_role_command_receipt`,
   `mentor_role_fence`: SHARE ROW EXCLUSIVE.

Failed-operation rollback gets a separate noncancelled cleanup context bounded
to one additional second. Five seconds is the operation deadline, not a strict
wall-clock return-time guarantee including cleanup.

Plain SELECTs then inspect the current committed values through this same
transaction. There is no pooled second-connection Admin check, role fallback,
authority cache or extra FOR UPDATE row lock. The canonical Admin tuple is
user / zero tenant / existing core service `...0100` / global / zero resource,
and must contain exactly one role, whose exact key is `admin`.
Replay is not exempt from this check.

All authority queries explicitly name public tables. The transaction and
migration search path explicitly place pg_temp last, so a temporary lookalike
cannot replace a locked canonical relation or a catalog type lookup.

The existing primary key includes role_id: locking only an existing Admin row
does not exclude insertion of another same-scope role. Existing signup/operator
writers also do not share a Mentor advisory lock. Table exclusion therefore
provides the conservative initial boundary without changing those writers.
This deliberately serializes low-volume administrative Mentor decisions and
temporarily blocks other assignment writes. Ordinary read-only queries are
not blocked by these modes. A finer-grained scheme needs a separately reviewed
shared writer/version protocol; the adapter never weakens locks on contention.

PostgreSQL rationale: [LOCK](https://www.postgresql.org/docs/16/sql-lock.html)
and [explicit locking](https://www.postgresql.org/docs/16/explicit-locking.html).
In particular, READ COMMITTED reads occur after lock waits; no previously
frozen repeatable-read snapshot is reused. Metadata locks precede assignment
locks, and extra row locks are avoided to prevent cycles with existing
operator transactions that already hold row locks.

No automatic retry occurs on timeout, deadlock, serialization or commit error.
Failures before commit roll back. A lost/uncertain commit acknowledgement is
**unavailable/unknown**, not proof of rollback: a later invocation needs a
fresh valid assertion and current Admin, then recovers the same durable command.
No post-commit authentication failure falsely claims the transaction was undone.

## Schema and metadata ownership (005)

Migration 005 is additive source code, not an applied migration. Discovery by
the existing migration runner is filename-driven; 001–004 and the canonical
six-role/base-core adoption profile remain unchanged.

It creates only dedicated `mentor` role metadata, `ms-go-mentor` service
metadata, their service_role mapping and three owner tables. It creates
**no principal assignment, permission, hierarchy or default/global role grant**.
If either logical key already exists, migration 005 rejects adoption instead
of overwriting or silently trusting it.

| Owner table | Invariant |
| --- | --- |
| mentor_role_scope | One immutable marker pins the generated role/service IDs; the service cannot be zero or core |
| mentor_role_command_receipt | Immutable command keyed by issuer/request; one command per application revision; original metadata IDs pinned |
| mentor_role_fence | One row indexed by application and uniquely by target/role/service; exact composite FK to its current immutable receipt |

Receipt columns store only the immutable business command, metadata IDs and
database timestamp. No bearer, raw JWT, assertion JTI or temporary proof digest
is persisted. The existing decision digest belongs to the durable command;
the separate exact-proof digest belongs only to the invocation.

The store resolves the marker, exact metadata keys/titles and service_role
mapping under locks. Absence, mismatch or drift denies the operation.
Application/target/metadata bindings cannot be reparented. The fence permits
only an initial APPROVE revision 2 or SUSPEND revision 3/4; an existing approval
may transition once to suspension. A suspended fence is terminal. Receipts
and the marker reject UPDATE/DELETE/TRUNCATE; fences reject DELETE/TRUNCATE
and any update other than the allowed immutable-binding transition.

DOWN first locks metadata, owner tables and all known metadata usage tables.
It refuses any receipt/fence history, metadata identity drift, principal or
other usage, or unknown foreign-key consumers. Only an empty owner schema and
the exact IDs recorded in its marker can be removed. It never guesses by key,
deletes durable history, or reverses a user's role. Its SQL and ledger removal
remain in the migration runner's transaction.

## Exact assignment and replay

The assigned tuple is:

```text
principal = verified target_user_id
principal_kind = user
role_id = immutable Mentor marker role ID
tenant_id = 00000000-0000-0000-0000-000000000000
service_id = immutable Mentor marker service ID (never core)
resource_kind = global
resource_id = 00000000-0000-0000-0000-000000000000
```

Here `global` means all resources **inside the dedicated Mentor service**,
not the canonical core/default assignment. Existing Student and unrelated
scopes are untouched. The adapter never calls `replacePrincipalRole`.

The store reads the immutable request receipt and both indexed fence views,
checks metadata pins and actual physical assignment against the current fence,
and delegates the allowed transition to `PlanMentorRoleCommand`.
Missing active assignment, surviving revoked assignment, inconsistent receipt
or fence, and an unowned pre-existing assignment are drift/conflict: no repair.

New approval inserts only the exact scoped assignment. Suspension removes only
that tuple and retains a terminal tombstone, including revoke-before-first-grant.
Receipt, fence and assignment commit together. A delayed approval or a different
application for a tombstoned target cannot restore access.

Exact command replay makes no receipt/fence/assignment writes. A historical
approval replay after suspension returns the old immutable approval receipt
**alongside the inactive current fence**, never a new grant. A renewed assertion
JTI is not a new operation. A changed command under the same request conflicts.

## Verification and remaining gates

Genuine RED→GREEN unit tests exercise admission/usecase behavior and the actual
PostgreSQL adapter against an isolated transactional pgx protocol fixture.
The fixture models locking/order, staged writes, rollback, contention,
lost-ACK replay, current-Admin changes and preservation of unrelated assignments.
It is **test-only**, never a production in-memory authority store.
Migration checks assert discovery, frozen history and DDL safety structure.
They do not execute or parse PostgreSQL SQL and are not migration acceptance.

Commands (no database):

```sh
go test ./internal/domain ./internal/usecase ./internal/infrastructure/persistence/postgres ./cmd/ms-rbac-migrate -run '^TestMentorRole' -count=1
go test -race ./internal/domain ./internal/usecase ./internal/infrastructure/persistence/postgres -run '^TestMentorRole' -count=1
go vet ./...
go build -buildvcs=false ./...
./scripts/check-agent-policy.sh
```

Full `go test ./...` must clear SQL opt-in configuration for a source-only run:
`env -u RBAC_SIGNUP_TEST_DATABASE_URL -u RBAC_MIGRATION_TEST_ADMIN_DSN -u RBAC_MIGRATION_TEST_ALLOW_CREATE_DATABASE -u T16_SERVE_RBAC go test ./...`.
It retains existing opt-in SQL skips; no new source test may be reported as
SQL PASS. Linked-worktree builds disable VCS stamping explicitly; source
identity is checked separately.

**Before activation:** separately approve and execute 005 UP/DOWN on an owned
disposable PostgreSQL environment; test real lock contention, concurrent grant/
revoke/replay, unique/FK/trigger enforcement, rollback and restart; confirm
preserved Student/current Admin. Then complete signed fresh nonce/proof-digest
bound scoped readback composition, Mentor live-session handoff/recovery and reviewed runtime
wiring. This internal result is not authenticated transport or fresh readback,
and cannot by itself finalize Mentor private access.

The separate [signed scoped readback](mentor-scoped-role-readback.md) now has
source adapters and producer/consumer conformance. It confirms only a current
exact receipt/fence/physical assignment, not this mutation method's replay
result. It remains disabled by default, with runtime acceptance pending the gates above.

Executable Gherkin belongs in `learning-platform-verification`; MENT-00
acceptance references remain available, but no Gherkin business PASS, MCP,
TeacherSoul change, service startup or full MENT-01A completion is claimed here.
