# Read-only Mentor canonical Admin confirmation

Status: **source-only, disabled by default**. Parent:
`bemulima/learning-platform-business#27`, MENT-01A.

This slice implements a real cryptographic request consumer, the existing
canonical-default role read through a narrow port, and a dedicated signed
response. This provider has no direct lifecycle or role mutation. Its separate
[default-off runtime](mentor-owner-runtime.md) owns explicit key/transport
configuration; no migration, SQL activation or authority cache is added. It does not
complete MENT-01A or replace the later transaction-level Admin recheck.

## Ownership and API

Auth owns the request and acceptance contract at
`ms-go-auth/.ai/contracts/mentor-owner-lookups-v1.{md,json}`. RBAC owns
[the reply manifest](../.ai/contracts/mentor-canonical-admin-decision-v1.json).
The Auth-owned canonical files are referenced, not copied here.

The lifecycle-independent provider is:

```go
(*nats.MentorCanonicalAdminConsumer).Handle(
    ctx context.Context, actualSubject string, body []byte,
) ([]byte, error)
```

Its ports are the dedicated `MentorAdminLookupProofVerifier`, read-only
`MentorCanonicalAdminChecker` and `MentorCanonicalAdminDecisionSigner`.
`usecase.NewMentorCanonicalAdminLookup` accepts only a
`MentorCanonicalAdminRoleReader`, exposing `GetDefaultRole(ctx, actorID)`.
The existing PostgreSQL `PrincipalRoleRepository` already implements this
method. No repository implementation or database query was changed.

The only accepted actual subject is `rbac.checkMentorCanonicalAdmin.v1`.
A future reviewed transport wrapper must pass the actual received message
subject, not a request header or configurable alias. No `Listen` or wildcard
registration is introduced.

## Admission and lookup ordering

1. Reject absent/cancelled context, wrong subject, unavailable dependencies and
   malformed or oversized exact one-proof envelopes before any role read.
2. Verify the distinct Auth lookup RS256 proof using the dedicated lookup
   public key. The final Mentor role-decision proof, reviewer proof, signup
   proof and ordinary access/refresh token are not lookup authority. Verify
   signature before payload interpretation, then exact nine claims, fixed
   subject/purpose, canonical UUIDs, safe integer times and lifetime.
3. Derive the actor solely from that verified proof and call the actual narrow
   `GetDefaultRole`. The exact default tuple is user / zero tenant / core
   service `...0100` / global / zero resource. The legacy any-scope `Get`
   fallback is not exposed to this usecase. Missing or non-admin roles give
   a known DENY; ambiguous rows or storage errors give no confirmation.
4. Reverify the **same exact compact proof bytes** after the read. Check that
   the recovered actor, nonce, subject, byte digest and timestamps are unchanged
   and still valid. Cancellation, expiry or an inconsistent result gives no
   signed response.
5. Sign an owner decision with a separately supplied RBAC reply private key.
   Recheck proof freshness before signing and freshness/cancellation after
   signing. The signature covers exactly the canonical twelve reply claims.

The signed request authenticates **Auth as the service caller**, not a user
session. The Auth role-decision issuer must still verify the actual live user
session before requesting this owner confirmation. No bearer or refresh token
is sent to RBAC, and a caller-supplied Admin ID is not accepted as a transport
credential.

## Reply, key custody and errors

A known ALLOW or DENY returns exactly `{"decision_jwt":"<signed JWT>"}`.
The response echoes the requested actor and concrete subject, generates a fresh
random response JTI, binds the original request JTI and SHA-256 of the exact
original compact proof bytes, and uses the distinct RBAC reply purpose.
Reply expiry is the smaller of `iat + 15 seconds` and the original request
expiry. Both timestamps are positive integers at most `9007199254740991`;
time arithmetic is bounded before subtraction/addition. The request remains
limited to 30 seconds with at most 5 seconds of future skew.

Keys are passed explicitly to `NewAuthMentorAdminLookupProofVerifier` and
`NewMentorCanonicalAdminDecisionSigner`. No existing runtime key variable is
reused or configured here. Empty key input yields an unavailable component;
malformed, multiple, wrong-type, or sub-2048-bit RSA key material fails
construction. Token-provided key metadata, alternate algorithms and unsigned
boolean replies are not supported.

Any invalid proof, corrupt/ambiguous or unavailable read, cancellation, missing
key, or signing failure returns **nil bytes and `domain.ErrAuthorityUnavailable`**
from `Handle`. A store error is never converted into signed DENY. Private
repository/verification/signing diagnostics do not escape in responses. No
request proof, response token, private key or live credential is logged or
persisted by these components.

## Currentness and deferred gates

Every accepted call rereads the current exact role. There is no positive cache,
automatic retry, request nonce reuse or role/receipt write. Auth independently
pins the RBAC reply key and must validate its fresh request binding, lifetime,
purpose and signature before treating ALLOW as its mandatory owner-port result.

This is a **point-in-time read**, not a cross-service transaction. Admin may
change after the confirmation. The later Mentor role mutation still needs
current canonical Admin authorization serialized with the role/receipt/fence
commit. Approval alone still cannot activate Mentor access without the separate
authenticated fresh scoped-role readback. Key distribution, broker ACLs,
runtime wiring and live-session/SQL acceptance remain separate gates.

## Verification scope

Behavior tests first ran against fail-closed stubs and failed on valid lookup,
read/sign ordering and known-state results, then passed against implementation.
Tests exercise real RSA request verification and reply signing with in-memory
keys, strict JSON/encoding/identity/time denial paths, canonical-role changes,
no caching, no legacy scope fallback, original-proof revalidation, nil/typed-nil
dependencies, cancellation, and response nonce/digest/expiry binding.

An outbound-adapter test also invokes the **actual existing PostgreSQL repository
method** over a query fixture and checks all six canonical tuple parameters.
That proves the source adapter path, not live PostgreSQL behavior. Cross-owner
conformance can invoke real Auth clients and this provider with controlled
read fixtures; it must not be described as live owner, broker, SQL, Gherkin or
complete MENT-01A acceptance.
