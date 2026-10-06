# Messaging contract

rbac.assign-role and rbac.checkRole remain queue-group Core NATS request/reply
subjects (queue ms-go-rbac), responding with ok and optional error. They are RPC
contracts, not durable events. checkRole remains read-only and accepts user_id
and role. Assignment accepts only the signed canonical Auth signup envelope
below. The legacy unsigned user_id/role body is denied, even with caller or actor
headers, broker connectivity, shared tokens, access tokens or refresh tokens.
There is no legacy mutation fallback and the consumer stays registered when
its authority is unavailable.

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
