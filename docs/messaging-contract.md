# Messaging contract

rbac.assign-role, rbac.checkRole, and rbac.checkPermission are queue-group Core
NATS request/reply subjects (queue ms-go-rbac). Assignment and role-check
responses retain their existing ok/error shape; permission success responds
with a signed decision_jwt while unavailable/error cases fail closed. They are
RPC contracts, not durable events. checkRole and checkPermission are read-only.
checkRole accepts user_id and role. `checkPermission` accepts only
the Auth-signed proof described below and checks the fixed
`knowledge_graph.review` permission; JSON identity and permission fields and
caller headers are not accepted. Assignment accepts only the signed canonical Auth signup envelope
below. The legacy unsigned user_id/role body is denied, even with caller or actor
headers, broker connectivity, shared tokens, access tokens or refresh tokens.
There is no legacy mutation fallback and the consumer stays registered when
its authority is unavailable.

## Auth reviewer permission lookup

The `rbac.checkPermission` request is exactly `{"proof":"<JWT>"}`. The proof
is a short-lived Auth assertion signed with RS256 using Auth's existing JWT RSA
key pair. RBAC reads the matching public PEM from `AUTH_JWT_PUBLIC_KEY` and pins
`AUTH_JWT_ISSUER` (which defaults to `auth-service`) plus audience
`ms-go-rbac-knowledge-review`. Missing public-key configuration keeps the
consumer fail-closed with an unavailable response; malformed configured keys
fail service composition. HMAC access tokens are never accepted as proofs.

The JWT header contains only `alg=RS256` and `typ=JWT`. Its exact claims are
`iss`, `aud`, `sub`, `typ`, `purpose`, `permission`, `jti`, `iat`, and `exp`.
RBAC requires the fixed proof type `knowledge_graph_permission_check`, purpose
`AUTH_RBAC_KNOWLEDGE_GRAPH_REVIEW_PERMISSION_V1`, and permission
`knowledge_graph.review`. `sub` and `jti` must be canonical non-zero UUIDs;
timestamps are integer Unix seconds, with at most five seconds of future skew,
an unexpired `exp`, and no more than 30 seconds between `iat` and `exp`. The
proof is signed only after Auth's protected middleware validates the session;
RBAC derives the subject from verified `sub` and does not read a subject or
permission from request JSON or headers.

## Signed permission decision

After a valid proof and the existing exact permission lookup, RBAC returns
exactly {"decision_jwt":"<RS256 JWT>"}. The JWT issuer is ms-go-rbac,
audience is ms-go-auth-knowledge-review-permission-decision, type is
knowledge_graph_permission_decision, and purpose is
RBAC_AUTH_KNOWLEDGE_GRAPH_REVIEW_DECISION_V1. Its exact claims are iss, aud,
sub, typ, purpose, permission, decision, jti, request_jti, request_digest,
iat, and exp. The permission remains knowledge_graph.review; decision is
exactly ALLOW or DENY. The response JTI is a newly generated canonical
non-zero UUID. request_jti is copied only from the verified Auth proof, and
request_digest is the lowercase SHA-256 digest of the exact proof bytes. The
decision is signed with the RBAC-only PEM private key from
RBAC_REVIEWER_PERMISSION_DECISION_PRIVATE_KEY. Its configured lifetime is 15
seconds and it cannot exceed the 30-second contract maximum.

If the signer key is absent or invalid, the proof is invalid, or the permission
store is unavailable, RBAC returns a generic error response without a signed
decision. A valid missing grant returns a signed DENY. Auth must reject every
unsigned boolean reply, invalid signature or claim, stale/mismatched request
binding, expired/overlong token, and replayed response JTI. The public key is
provided separately to Auth as AUTH_RBAC_PERMISSION_DECISION_PUBLIC_KEY; no
key material is stored in source or shared with Auth as a private key.

RBAC checks only the subject's unique principal-role binding at the canonical
user/global default tuple (zero tenant, the `core` service, global resource
kind, and zero resource ID). It requires the role-permission link at the default
zero resource ID and exact permission fields `action=knowledge_graph.review`
and empty `resource_kind`. Missing roles or permissions produce a signed DENY.
Ambiguous default-scope role bindings, verification failures, or storage
failures deny the lookup; dependency details are not returned. The lookup
itself creates no grants and does not activate reviewer publication.

## MCP Student signed role readback — DORMANT candidate (MCP-00C3D1)

Parent: [MCP Epic #53](https://github.com/bemulima/learning-platform-business/issues/53).
`MCPStudentRoleChecker` is source-only and **not registered in bootstrap**.
The distinct future Core NATS request/reply subject is
`rbac.checkMCPStudentRole` (queue `ms-go-rbac`); it is NOT a variant of the
legacy unsigned `rbac.checkRole` or the active reviewer `rbac.checkPermission`.
No operator should route traffic to it until both owners have approved the
Auth-issued proof and Auth-side decision verifier/consumer.

The only request field is `{"proof":"<JWT>"}` (max 9 KiB envelope). An Auth
RS256 proof uses the existing configured Auth public verification key and
issuer but **separate, exact** audience `ms-go-rbac-mcp-student-role`,
type `mcp_student_role_check`, purpose `AUTH_RBAC_MCP_STUDENT_ROLE_V1`, and
`role=student`. Its exact JWT header is `alg=RS256, typ=JWT`, with claims
`iss,aud,sub,typ,purpose,role,jti,iat,exp`, canonical lowercase nonzero UUID
`sub` and `jti`, at most 30 seconds from `iat` to `exp`, at most 5 seconds
of future `iat` skew. The raw role claim is a fixed request purpose, **not
evidence of RBAC assignment**. Extra or duplicated fields, unsigned `ok`,
wrong-purpose reviewer JWTs, wrong keys, and public user headers are denied.

RBAC checks the **current, unique role at the canonical default user/global
scope** via `GetDefaultRole`. It returns signed `DENY` when that role is
absent or not exactly `student` (including `admin`). Other-scope fallback
from `GetByRole` is never consulted. An ambiguous default role, unavailable
storage, malformed signature, or missing signing key returns only a generic
error, not a successful unsigned decision.

For a valid proof and successful lookup the reply has exactly
`{"decision_jwt":"<RS256 JWT>"}`. It uses issuer `ms-go-rbac`, audience
`ms-go-auth-mcp-student-role-decision`, type
`mcp_student_role_decision`, purpose
`RBAC_AUTH_MCP_STUDENT_ROLE_DECISION_V1`, fixed role `student`, `ALLOW` or
`DENY` decision, a fresh canonical nonzero response `jti`, the verified
request `request_jti`, a lowercase SHA-256 `request_digest` of the complete
raw Auth proof, and integer `iat/exp` limited to 15 seconds. The exact JWT
fields are `iss,aud,sub,typ,purpose,role,decision,jti,request_jti,request_digest,iat,exp`.
Only RBAC holds the future **dedicated** private decision key; Auth must
validate its matching public key, strict response shape, signature, audience,
purpose, subject, request binding, freshness and replay before any token
exchange. Configuration and runtime wiring are deliberately deferred.

**This is a role-only decision**. It does not grant `courses:read`,
`tasks:write`, or any other MCP scope and cannot populate
`RBACStudentScopes` in Auth token intent. Auth must separately implement a
reviewed scope-to-RBAC/owner-policy mapping, then join it with its fresh
client/consent snapshot. No OAuth token or MCP endpoint is activated.

## MCP Student pilot read-scope policy — DORMANT (MCP-00C3D3)

This is an internal **source-only** evaluator layered after the canonical
Student role lookup, not a new request/reply subject or JWT decision. The
exact pilot mappings are `profile:read` → `mcp.profile.read`, `courses:read`
→ `mcp.courses.read`, and `tasks:read` → `mcp.tasks.read`; all map to empty
`resource_kind` at the canonical default zero resource ID. Each must have its
own explicit current `student` role-permission link; none are seeded here.
Absence means DENY; `admin`, ambiguous/non-default roles, unknown or write
scopes, and unavailable storage cannot authorize read scopes. The requested
set must be strictly sorted and duplicate-free and contain one to three pilot
scopes. Errors never yield partially allowed scopes.

See [pilot policy](mcp00-student-read-scope-policy.md) for the exact local
contract and the still-missing signed Auth↔RBAC scope request/decision,
Auth client/consent/platform-policy intersection, and domain-owner object ACL.
The existing signed role-only candidate stays dormant and must not be used to
mint token scope claims. No MCP runtime is enabled by this policy.

## MCP Student signed scopes readback — DORMANT RBAC producer (MCP-00C3D4A)

The additional, **unsubscribed** Core NATS subject is
`rbac.checkMCPStudentScopes` (queue `ms-go-rbac`). It accepts only the exact
`{"proof":"<JWT>"}` request. The signed Auth proof has distinct exact
audience `ms-go-rbac-mcp-student-scopes`, purpose
`AUTH_RBAC_MCP_STUDENT_SCOPES_V1`, type `mcp_student_scope_check`, and nine
claims: `iss,aud,sub,typ,purpose,scopes,jti,iat,exp`. All one to three
requested scopes must be sorted, distinct and among the three explicit
read-only pilot scopes above. JWT signature, strict shape, canonical subject,
freshness and purpose are verified before policy evaluation. The role-only
Auth proof cannot replace it.

On successful evaluation the response has only a signed `decision_jwt` with
exact `requested_scopes` and `allowed_scopes`, fresh `jti`, bound
`request_jti` and SHA-256 of the exact raw proof, 15-second TTL and distinct
audience/type/purpose. RBAC signs **only** the explicit permission-granted
subset (which can be empty); a missing key, ambiguous role, failed proof or
permission store outage returns a generic error without a signed decision.
The decision private key remains RBAC-only and is **not provisioned** here.

The [producer contract](mcp00-student-scope-decision-source.md) documents all
claims and the still-missing Auth consumer. Auth must separately verify the
signed scopes, client/consent/platform policy, fresh grant and owner ACL.
No OAuth tokens, bootstrap subscriptions or data access are activated.

## Dedicated Auth signup proof

The application boundary is
[AUTH_RBAC_STUDENT_PROVISIONING_V1](../.ai/contracts/auth-rbac-student-provisioning-v1.md).

Auth owns the dedicated Ed25519 private key. RBAC receives only its public key
in AUTH_SIGNUP_PUBLIC_KEY: standard base64 encoding of exactly 32 bytes. Empty
configuration makes provisioning unavailable/denied; malformed nonempty key
fails composition before database connection. Auth's paired signing configuration
is AUTH_RBAC_SIGNUP_PRIVATE_KEY, standard base64 of the 64-byte private key.
Operators must supply a dedicated matched pair and retain private-key custody
in Auth; no key, shared secret or production credential is embedded here.

The envelope has exactly key_id, payload and signature. key_id is auth-signup-v1;
payload and signature are canonical standard base64. The entire envelope is
bounded to 16 KiB and decoded payload to 8 KiB. The signature covers the exact
payload bytes. Signature verification precedes payload parsing; both JSON
objects reject unknown, duplicate, missing, null, mistyped or trailing fields.

The payload fields are version=1, issuer=ms-go-auth, audience=ms-go-rbac,
purpose=signup-student-provisioning-v1, subject matching the actual concrete
listened NATS subject, persisted operation_id, reserved canonical principal_id,
role=student, principal_kind=user, tenant_id=00000000-0000-0000-0000-000000000000,
service_id=00000000-0000-0000-0000-000000000100, resource_kind=global,
resource_id=00000000-0000-0000-0000-000000000000, issued_at and expires_at.
Both operation and principal identifiers must be lowercase canonical non-nil
UUIDs. Timestamps are integer Unix seconds: issued_at may be at most five seconds
in the future, expires_at must exceed now and issued_at, and lifetime is at most
60 seconds. Auth signs now and now+60. Each retry/replay requires a fresh valid
proof; a stored receipt never substitutes for authentication.

After proof admission, a dedicated signup application/repository atomically
creates the default student assignment and immutable receipt. Same binding
replay succeeds without writes; issuer/operation or issuer/principal reparenting
and any existing different default role conflict. Target/role/scope come only
from the verified payload. Authority failure, invalid proof, conflict and database
failure return distinct generic negative ACKs without proof or dependency detail.
An authenticated fresh Auth operation carrying a different role or default scope
returns conflict before storage. A non-student initial operation is also rejected
as an incompatible contract binding. Changed principal for the same operation
conflicts with its stored receipt. Exact replay and retry after a committed but
lost ACK reconstruct the same `{"ok":true}` response without rewriting rows.

This authenticates the existing accepted Auth signup business flow: verified
persisted signup operation, durable User ACK, canonical student assignment and
checkRole confirmation before terminal completion and tokens. No administrative
grant or unrestricted internal caller is introduced. Other generic mutation
callers lose unsigned assignment authority; unknown grant policy remains
HUMAN_POLICY_DECISION_REQUIRED. Auth, User and other consumers must follow their
owned policy rather than manufacture signup authority. Public role readback and
HTTP reads are preserved.

Verified canonical default-scope `admin` is Super Admin and receives reviewer ALLOW without an individual `knowledge_graph.review` grant. Other roles retain exact permission lookup. Caller role headers and non-default assignments never establish this authority.
