# Signed Mentor scoped-role readback

Status: **source-only, default-off executable wiring, SQL/runtime acceptance NOT_RUN**.
Parent: `bemulima/learning-platform-business#27`, MENT-01A.

Mentor owns the lookup request in
`ms-go-mentor/.ai/contracts/scoped-role-readback-request-v1.json`.
RBAC owns [the response contract](../.ai/contracts/mentor-scoped-role-readback-v1.json).
The existing Auth mutation assertion and RBAC mutation store are unchanged.

## Authority and exact binding

The only subject is `rbac.checkRoleScoped.v1`. The envelope contains exactly
one `proof` signed by a dedicated Mentor **service** key. The target (`sub`),
original Admin, application, committed decision revision, APPROVE/SUSPEND,
business request ID, decision digest and fixed `mentor` / `ms-go-mentor` scope
are exact signed binding fields, not current user authority. The durable
command issuer is implicitly fixed to `ms-go-auth`, never caller-selected.
APPROVE revision 2 and SUSPEND revision 3/4 retain the existing digest format.

Regular access JWTs, Auth grant/owner-lookup proofs, unsigned requests and
legacy role RPCs cannot substitute. The original granting Admin is **not**
reauthorized during this read: removing that Admin later does not itself revoke
an existing Mentor entitlement. Current Admin is a mutation-time requirement.

## One authoritative snapshot

`repo.NewMentorRoleReader(pool)` implements the domain reader port.
`usecase.NewMentorRoleReadbackLookup(reader)` validates inputs/results without
owning SQL. The reader uses one **REPEATABLE READ / READ ONLY** transaction,
an operation context at most five seconds (earlier deadlines win), local lock
timeout two seconds and statement timeout four seconds. Failed-call rollback
has a separate cleanup budget up to one second. No explicit row/table locks,
Admin queries, mutation planner, repairs or assignment writes are performed.

The snapshot includes marker-owned metadata and exact IDs, the immutable
requested receipt, both current application/target fence indexes, and the
physical dedicated service-scoped assignment. Existing owner SQL validators
are reused with explicit `public` qualification and
`pg_catalog,public,pg_temp` search path. Only exact `pgx.ErrNoRows` is absence;
joined/wrapped failures cannot become semantic denial.

| Coherent owner state | Signed result |
| --- | --- |
| Exact current APPROVE receipt/fence and physical assignment | `ALLOW / ACTIVE` |
| Exact current SUSPEND receipt/fence and no physical assignment | `ALLOW / INACTIVE` |
| Known absence, valid mismatch or approval superseded by suspension | `DENY / UNCONFIRMED` |
| Missing metadata, drift, dangling receipt, ambiguity or failed read | No signed semantic answer; generic unavailable |

Related current snapshots and physical state are validated even for coherent
mismatched application/target requests. Replies echo only the requested binding,
never an actual foreign/superseding command. Historical receipts are not current
entitlement; Student/default and unrelated scopes are not fallback authority.

## Signed transport

`client.NewMentorRoleReadbackProofVerifier` admits the dedicated request.
`MentorRoleReadbackConsumer.Handle` performs verify, read, exact reverify, sign.
`NewMentorRoleReadbackDecisionSigner` requires a matched RBAC reply key pair.
No subscription or runtime key is configured by these components.

The exact 17-claim request and 21-claim reply use RS256/JWT, RSA >=2048,
canonical unpadded base64url and lowercase nonzero UUIDs. Strict JSON rejects
unknown/missing/duplicate/escaped-duplicate/null/mistyped/case-alias/trailing
fields and invalid UTF-8. Tokens are <=8192 bytes, envelopes <=16384. Positive
integer Unix times are <=9007199254740991. Request TTL is <=30 seconds, reply
TTL <=15 seconds and capped to request expiry, future skew <=5 seconds.

The reply binds the request nonce and SHA-256 of the exact original compact
proof bytes. A distinct fresh response JTI is not a grant ID. After confirmed
response verification, the consumer derives the stable receipt ID as
`ms-go-auth:<business request_id>` and the exact reply digest as provenance.
Neither proves ongoing permission. Signing rechecks original/reply expiry and
cancellation at final return. No raw proof/bearer persistence, retries or cache.

This is point-in-time readback, not a distributed revocation lock. A role can
change after the snapshot/signature. Mentor must retain its final local
approval/receipt re-read; future private writes need owner revision fencing.

## Verification and remaining gates

Compiled RED→GREEN tests exercise real crypto and actual production reader
methods through a test-only pgx fixture, including mutation-adapter facts,
concurrent snapshots, drift, history and errors. **No SQL is executed.**
Use named `mentor-role-readback-tests` / `mentor-role-readback-race` commands.
Full source tests must clear the four SQL/T16 opt-ins documented in
[mentor-role-owner.md](mentor-role-owner.md).

From the matching Mentor checkout run:

```sh
node scripts/test-scoped-role-readback.cjs --rbac /absolute/path/to/ms-go-rbac
```

The runner builds tagged bridges and exercises the actual client, verifier,
handler, usecase and signer through private pipes over a controlled reader.
Keys/JWTs stay in memory and are not printed; owned temporary binaries are
removed. Hostile transport cases replay/tamper/substitute replies. This is not
PostgreSQL, live NATS or Gherkin acceptance.

Remaining gates: Mentor current-session handoff and exact-binding RoleAuthority
integration/recovery; separately authorized disposable PostgreSQL acceptance;
key custody/distribution and broker ACLs; owner/Gateway/runtime integration.
The separate [default-off runtime](mentor-owner-runtime.md) now wires this
consumer. No migration, service startup or full MENT-01A completion is claimed.
Executable Gherkin and MENT-00 relocation belong in
`learning-platform-verification`.
