# RBAC_MENTOR_ROLE_MUTATION_RPC_V1

Owner: RBAC. Consumer: Mentor. Parent: `bemulima/learning-platform-business#27`.
Status: **source-only, unmounted, SQL/runtime acceptance NOT_RUN**.
The machine-readable companion is [mentor-role-mutation-rpc-v1.json](mentor-role-mutation-rpc-v1.json).

This additive wire contract exposes the existing
[atomic owner application](../../docs/mentor-role-owner.md), not a second grant
implementation. Auth continues to own the exact signed assertion in
`ms-go-auth/.ai/contracts/mentor-role-decision-v1.{md,json}`; those claims and
keys are not redefined here. Legacy Student signup, generic role reads and the
unconditional denial of legacy HTTP writes remain unchanged.

## Request and admission

The only concrete subject is `rbac.applyMentorRole.v1`. Its request is exactly
`{"proof":"<original compact Auth role-decision JWT>"}`: one required non-null
string, at most 8192 bytes, inside a UTF-8 JSON envelope at most 16384 bytes.
Unknown, duplicate (including escaped-equivalent), missing, null, mistyped,
case-aliased or trailing fields are rejected. An empty/whitespace proof is
invalid. No independent actor, target, role, service, revision or caller header
is accepted as authority. The original proof bytes, not reconstructed claims,
reach `usecase.MentorRoleMutation.Apply` unchanged.

`nats.MentorRoleMutationConsumer` depends on the actual
`*usecase.MentorRoleMutation`, not a generic assignment interface. That use case
performs the real Auth signature/claim admission and exact revalidation before
and inside the existing atomic store. The store independently rechecks current
unique canonical Admin, including replay, in the same transaction as the
receipt/fence/scoped assignment. A JSON decoder or caller-created Go plan cannot
grant a role. Missing verifier/store/key configuration fails closed.

## Reply and error taxonomy

The success reply is exactly `{"ok":true}`. It is only an unsigned transport
acknowledgement and is **not** permission, a receipt or a current role assertion.
Mentor must still obtain its fresh, nonce/digest-bound, signed exact-command
scoped readback before finalization. No internal receipt, fence, historical
`Applied.Active`, current state or command fields are exposed in the reply.

Semantic rejection returns exactly one `error` string:

| Value | Meaning |
| --- | --- |
| `invalid_proof` | Invalid envelope or exact unauthenticated/invalid-command result |
| `forbidden` | Exact current canonical-Admin denial |
| `conflict` | Exact command conflict or stale revision |
| `unavailable` | Authority/store failure, invalid snapshot or any unknown/mixed/wrapped error |

Only exact sanitized sentinels are classified. The existing mutation use case's
error normalization is narrowed accordingly: a joined/wrapped denial plus an
outage cannot masquerade as a known semantic denial. This is the sole change to
existing mutation orchestration; the atomic store and all migrations stay
unchanged. Error text, SQL details, proof bytes and keys are never returned.

Wrong subject, nil handler/concrete mutation/context or cancelled invocation returns
no response body and generic `ErrAuthorityUnavailable`. The consumer maps a
transport failure, malformed/unknown/extra-field reply, `invalid_proof`,
`conflict` or `unavailable` to unavailable/unknown outcome. Only exact `forbidden`
may retain that category. There is no unsigned or legacy assignment fallback.

## Deadlines, commit and retry

The handler gives the mutation an operation context of at most five seconds,
preserving earlier deadlines. It retains no proof, callback, response cache or
background retry. Existing store rollback cleanup may take up to one additional
second; the operation deadline is not a stricter total wall-clock guarantee.

Commit error, cancellation after commit or lost reply is an unknown outcome to
the caller, **not proof of rollback**. A later explicit authenticated Mentor
invocation obtains fresh Auth proof for the same immutable command and recovers
the durable receipt/fence. A renewed assertion JTI is not a new operation.
Historical APPROVE replay after SUSPEND may ACK its old command while current
role stays inactive; only the separate signed readback decides currentness.

## Mounting and verification boundary

`Handle(ctx, actualSubject, body) ([]byte, error)` has no `Listen` method and does
not register a subscription or alter bootstrap. Future Core NATS wiring must
use the service queue group, preserve exact subject/body handling and enforce
reviewed broker credentials/ACLs. No HTTP mutation endpoint is introduced.

Targeted tests use the actual handler, actual Auth proof verifier and actual
mutation use case, with ephemeral test signing keys and a controlled store.
They cover malformed/adversarial inputs, denial/error sanitization, deadlines,
uncertain commit/replay and suspension. This is not live SQL, broker or business
Gherkin acceptance. Existing PostgreSQL fixtures do not prove real lock behavior.
Before activation, separately accept pinned key custody, broker authorization,
isolated PostgreSQL and owner/Gateway/runtime integration. No migrations,
service startup, public route, deployment or full MENT-01A completion is implied.
