# MCP-00C3D4A: signed Student scope decision producer (dormant)

Parent: [MCP Epic #53](https://github.com/bemulima/learning-platform-business/issues/53).
Depends on MCP-00C3D1 (role-only decision) and MCP-00C3D3 (exact read-only
scope mappings). This **RBAC producer-only candidate is not registered in
bootstrap** and cannot authorize a live OAuth token or object read.

## Distinct Auth → RBAC proof (future)

The only proposed Core NATS request is `{"proof":"<JWT>"}`, at most 9 KiB,
on a separate subject `rbac.checkMCPStudentScopes` (queue `ms-go-rbac`).
No untrusted `student_id`, `role`, `scopes`, `client_id` or authorization header
may be supplied outside the signed proof. No active NATS subscription exists.

The Auth RS256 JWT header has exactly `alg=RS256,typ=JWT`. The payload has
exactly nine claims: `iss,aud,sub,typ,purpose,scopes,jti,iat,exp`.

| Claim or constraint | Exact value |
| --- | --- |
| `iss` | Configured Auth issuer; public key from Auth's existing trusted public key |
| `aud` | `ms-go-rbac-mcp-student-scopes` |
| `typ` | `mcp_student_scope_check` |
| `purpose` | `AUTH_RBAC_MCP_STUDENT_SCOPES_V1` |
| `sub`, `jti` | Lowercase canonical nonzero UUIDs |
| `scopes` | Sorted, distinct, nonempty array of 1–3 exact read-only pilot scopes |
| `iat`, `exp` | Integer Unix seconds; at most 5 seconds future skew, max 30 seconds TTL |

The proof must be signed **only after** Auth has authenticated the Student and
read a fresh Auth-owned client, consent, resource and account snapshot. It is
not the existing signed role-only proof; neither reviewer nor role-only JWTs
are accepted. The RBAC verifier detects extra/duplicate/null/mistyped fields,
noncanonical JWT encoding, wrong key/issuer/audience/purpose, invalid
signature, expiry, duplicates, unknown and write scopes before any RBAC lookup.

## Exact RBAC check and signed decision

RBAC reads the unique current canonical default role. Only exact `student`
may proceed. It queries each exact permission at the zero resource ID and
empty resource kind: `profile:read → mcp.profile.read`, `courses:read →
mcp.courses.read`, `tasks:read → mcp.tasks.read`. A missing grant gives no
scope. Other roles, including `admin`, get a signed **empty** allowed subset.
Ambiguous roles, store outage or invalid proofs return a generic error with
no signed decision or partial grants.

The proposed response has only `decision_jwt` (or a generic `error`), never
an unsigned boolean or bare scope array. RBAC signs the exact twelve claims
`iss,aud,sub,typ,purpose,requested_scopes,allowed_scopes,jti,request_jti,request_digest,iat,exp`
using a **dedicated future RBAC private signing key**, separate from all
reviewer and role-only decision identities.

| Claim | Contract |
| --- | --- |
| `iss` | `ms-go-rbac` |
| `aud` | `ms-go-auth-mcp-student-scopes-decision` |
| `typ` | `mcp_student_scopes_decision` |
| `purpose` | `RBAC_AUTH_MCP_STUDENT_SCOPES_DECISION_V1` |
| `sub` | Verified Auth proof subject |
| `requested_scopes` | Exact sorted array from the verified proof |
| `allowed_scopes` | Sorted explicit subset, possibly `[]`; never `null` |
| `jti` | Fresh lowercase canonical nonzero response UUID |
| `request_jti` | Verified Auth request JTI |
| `request_digest` | Lowercase SHA-256 of the exact raw Auth proof bytes |
| `iat`, `exp` | Integer Unix seconds; 15 second TTL |

The signer checks a non-nil evaluated subset, strict membership/order and
matching proof digest, preventing an accidental empty-vs-uncomputed decision
or response binding to the wrong raw proof. No role-only `ALLOW` is projected
into `allowed_scopes`. Zero permissions are seeded or issued here.

## Explicitly not implemented / required next

- Auth-owned signer and response verifier/consumer, replay-JTI registry,
  exchange-time request binding, strict subject/requested-scope validation.
- Auth composition of `requested ∩ client ∩ consent ∩ platform-policy ∩
  RBAC-allowed` scopes after consuming the code and verifying the grant again.
  A signed empty subset must never be elevated by copying consent scopes.
- Domain owner's object-level ACL for actual profile/course/task data access.
- Future key provisioning/configuration, NATS subscription, token issuance,
  runtime E2E and migration. No write scope is included or approved.

The source implementation is intentionally separate from the active reviewer
permission and legacy `rbac.checkRole` requests. Producer-only source checks
do **not** demonstrate a live client↔RBAC round trip.
