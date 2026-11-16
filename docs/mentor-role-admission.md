# Mentor role admission and pure revision-fence planner

Status: **source-only, disabled by default**. The separate
[atomic owner adapter](mentor-role-owner.md) now exists in source;
PostgreSQL acceptance and runtime authority are not established by these files.
Parent task: `bemulima/learning-platform-business#27`, MENT-01A.

This document covers the cryptographic consumer and pure domain planner.
The following owner slice adds a PostgreSQL adapter and source
migration 005 for dedicated metadata, receipts and terminal fences. Neither
slice adds a route, subscription, runtime key configuration, production
in-memory repository or service activation. Existing signup, reviewer,
default Student, operator and CAT behavior remains unchanged. MENT-01A is
not complete on this evidence.

The subsequent [default-off executable runtime](mentor-owner-runtime.md) wires
the existing owner components without changing this admission contract.

## Contract ownership and admission

Auth owns the canonical assertion contract at
`ms-go-auth/.ai/contracts/mentor-role-decision-v1.md` and its adjacent JSON
manifest. Those files are not copied into RBAC. Mentor owns the committed
application lifecycle and decision intent. RBAC owns this admission code and
its separate assignment, immutable receipt and revision-fence transaction.

`client.NewAuthMentorRoleProofVerifier(publicKeyPEM)` accepts one separately
supplied Mentor RSA public key. Missing configuration yields an unavailable
verifier; malformed, multiple, non-RSA or sub-2048-bit keys fail construction.
Key lookup from token metadata and algorithm fallback are not implemented.
No assertion/private key is logged or retained.

`VerifyMentorRoleProof(ctx, token)` performs bounded canonical JWT parsing,
fixed-header checking and real RS256 verification **before interpreting the
payload**. It then checks the exact Auth-owned 16-field claim set, all fixed
identity/purpose/scope values, canonical nonzero UUIDs, Mentor's existing
decision digest, legal v1 decision/revision pairs, and the short lifetime. Both
timestamps are positive safe integers at most `9007199254740991`; TTL/skew use
subtraction only after validating bounds. Duplicate (including escaped-equivalent),
unknown, missing, null, case-alias, mistyped and trailing JSON is rejected.
Numeric exponent and fractional forms are not admitted as integers.

Success returns a value-only `domain.MentorRoleProof`: immutable `Command`,
assertion `JWTID`, SHA-256 `ProofDigest` of exact compact proof bytes, and issue/
expiry timestamps. It performs **no role, receipt, fence or store operation**.
These fields are not independently trusted if a caller fabricates a struct.
Constructing a command or calling the pure planner does not authenticate anyone.

The consumer does not transform the Mentor digest to include target identity.
The existing digest binds decision/Admin/application/request/expected revision;
the target is independently signed, must be confirmed by Auth against the
Mentor owner, and is pinned by RBAC's bilateral immutable bindings.

## Pure planner contract

```go
PlanMentorRoleCommand(command MentorRoleCommand, snapshot MentorRoleSnapshot) (MentorRolePlan, error)
```

The snapshot consists of three exact lookups from one serialized view:

| Value | Required lookup |
| --- | --- |
| `Receipt` | Immutable command key `(issuer, request_id)` |
| `ApplicationFence` | Immutable owner binding for `application_id` |
| `TargetFence` | Immutable owner binding for `(target_user_id, role, service)` |

Nil means authoritative absence, never an unavailable/skipped lookup. If either
fence exists, both exact views must exist and agree. Both indexes independently
pin the same application, target, fixed Mentor role and fixed Mentor service.
Application-to-target and target/scope-to-application reparenting are denied;
using a newly invented application cannot evade a suspended target tombstone.

Each `MentorRoleFence` contains its last immutable `Command`, `Active` and
terminal `Suspended` state. Each receipt contains the immutable original command
and its historical `Applied` fence. The planner never edits input pointers and
returns value copies.

| Existing state | Exact new command | Result |
| --- | --- | --- |
| No receipt/fences | APPROVE revision 2 | Plan active scoped Mentor state + immutable receipt |
| No receipt/fences | SUSPEND revision 3 or 4 | Plan an inactive terminal tombstone, even if no grant ever existed |
| Active APPROVE revision 2 | SUSPEND revision 3 or 4 | Plan inactive terminal state + new immutable receipt |
| Suspended revision 3 or 4 | Delayed APPROVE revision 2 without receipt | Reject stale revision; no grant resurrection |
| Any consistent current state | Exact known command and receipt | Historical receipt + current fence, `Replay=true`, `Write=false` |
| Existing request key | Different valid command binding | Conflict; no writes |
| Any existing fence | Different application/target binding | Conflict; no reparenting |
| Suspended state | Another command | Reject; v1 has no reactivation or new suspension after termination |

The special historical case matters: replay of an old successful APPROVE after
SUSPEND returns an active **historical** receipt but an inactive **current**
fence. It does not restore, repair, allocate or rewrite a grant. A missing
receipt for the currently applied command is inconsistent storage, not an
invitation to synthesize evidence. Invalid or mismatched snapshots fail closed.

`Write=true` is only a proposed state transition. It is neither a persistent
role grant nor evidence that a real user, Admin or database was consulted.
`Replay=true` likewise proves only consistency of the supplied snapshot. A
future current scoped readback, not the historical receipt, establishes actual
assignment state for Mentor finalization.

## Mandatory composition prerequisites

The [atomic owner implementation](mentor-role-owner.md) supplies the following
transaction protocol in source. SQL behavior is still NOT_RUN, and fresh signed
scoped readback is still a following slice. These requirements remain mandatory
before any endpoint or runtime is composed.

The source helpers MUST NOT be composed as a mutation endpoint before all of
the following owner work is implemented and accepted:

1. Authenticate this exact fresh Auth assertion before every invocation,
   including replay, and before any caller role/receipt/fence/store use. Never
   reconstruct authority from a stored Admin ID, old receipt or caller headers.
2. Recheck the actor's **current unique canonical-default Admin** assignment.
   Do not use the legacy any-scope role fallback, a Student-only RPC, JWT role
   claim or cached boolean. A missing/ambiguous/unavailable canonical lookup
   denies access. An Admin check made during Auth issuance does not substitute
   for this RBAC check.
3. Serialize canonical Admin currentness with the role mutation: acquire the
   exact authority/fence locks or use validated versions inside the same atomic
   transaction. A successful Admin check followed by an unprotected separate
   commit is insufficient. Replay must also pass current Admin authorization.
4. Atomically load all three snapshot keys; enforce unique immutable
   `(issuer, request_id)`, `application_id -> target`, and
   `(target, role, service) -> application` constraints. Lock in a consistent
   order, compare the revision fence, and atomically commit receipt, both fence
   views and the exact scoped assignment. Database failure or uniqueness/CAS
   conflict must roll back the complete change. A pure planner cannot provide
   this concurrency guarantee.
5. Keep SUSPEND tombstones and immutable receipts even when no active assignment
   exists. Never delete/reparent a tombstone to accept an older approval or a
   new application. The current fixed v1 lifecycle has no reactivation.
6. Create/revoke only the fixed Mentor service scope. Preserve the user's
   existing canonical-default Student assignment and unrelated scopes. Missing
   or ambiguous scope/role metadata must deny; source migration 005 creates only
   dedicated metadata with an immutable ownership marker, never principal grants.
7. Return an authenticated fresh scoped readback tied to a new lookup nonce,
   the exact presented proof-byte digest and the current application/target
   fence. An old receipt, stable operation request ID or unsigned boolean is
   not sufficient for Mentor to activate access. This transport is not included.
8. Keep assertion JTI distinct from the durable operation key. A renewed proof
   for the same immutable command may replay without writes, but cannot mint a
   new grant. Do not persist bearer/refresh tokens or raw assertions.

The store and canonical-Admin lookup providers are source-only and disabled by default.
SQL durability, live session validation, authenticated owner transports,
broker authorization, migration behavior, actual Student-role preservation and
Mentor runtime activation remain **not verified**, not implicitly passing.

## Verification

Focused Go tests cover real RSA signature admission, exact claims, time/format
boundaries, invalid keys, cross-purpose denial, tampering, bilateral bindings,
revoke-first ordering, immutable replay, inconsistent snapshots and terminal
revocation. Tests generate private keys in memory; they do not contain tokens
or runtime credentials. The same positive behavior tests first failed against
fail-closed stubs and then passed against the implementation (RED -> GREEN).

Use the repository's existing `go test ./...`, `go vet ./...`, formatting and
agent-policy checks. Cross-owner byte conformance can consume the real Auth
issuer output with this verifier using ephemeral test-only keys; it must not
be reported as live Auth/RBAC or SQL acceptance.
