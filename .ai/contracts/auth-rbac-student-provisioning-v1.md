# AUTH_RBAC_STUDENT_PROVISIONING_V1

Status: accepted signup application contract.

Auth owns the canonical signup orchestration; RBAC owns its student assignment
and durable receipt. This boundary is implemented by `SignupProvisioner` and
`SignupProvisioningRepository`, separately from `PrincipalRoleUsecase.Update`.
The existing `rbac.assign-role` RPC carries the dedicated signed signup envelope;
it does not extend the generic role mutation API.

Only the persisted canonical Auth signup operation, after identity verification,
canonical principal creation and durable User acknowledgement, supplies the
operation UUID and principal UUID. Auth's `AssignSignupRole` port has no role or
scope arguments. Its adapter fixes role `student` and the existing scope:
principal kind `user`, tenant `00000000-0000-0000-0000-000000000000`, service
`00000000-0000-0000-0000-000000000100`, resource kind `global`, resource
`00000000-0000-0000-0000-000000000000`. Frontend actor metadata is not authority.
Exact credential-owned T16 recovery continues the same persisted operation.

The existing dedicated Auth Ed25519 proof authenticates this service boundary.
Malformed or unavailable proof is denied before receipt access. A valid fresh
Auth proof with an incompatible role/scope returns `signup provisioning conflict`
before storage, including a non-student initial request. A changed principal
for the same issuer/operation conflicts against the durable receipt. No conflict
creates or changes an assignment or receipt.

Assignment and immutable receipt commit in one PostgreSQL transaction. The
receipt key is `(issuer, operation_id)` with unique `(issuer, principal_id)`;
its principal/student/scope tuple is immutable. Exact replay returns the same
`{"ok":true}` result without rewriting either row. A fresh proof after a lost
ACK reconstructs that result from the receipt, including after application and
database pool reconstruction. Proof timestamps are not the operation identity.
Other scoped assignments remain untouched; an existing different default role
conflicts. Auth still requires role readback before terminal completion/tokens.

No role/permission model or administrative grants are introduced.
Generic HTTP/admin operations retain their existing admission behavior.
General administrative role grant policy: `HUMAN_POLICY_DECISION_REQUIRED`.

Verification: `TestAuthRBACStudentProvisioningV1Contract` uses an opt-in isolated
PostgreSQL database, real verifier/usecase/repository, and a named lost-ACK wrapper
after commit. Existing SQL tests cover atomicity and concurrent exact replay.
Auth's `TestAuthRBACStudentProvisioningV1RetriesCommittedAssignment` checks the
canonical producer flow and no-token failure boundary. T16/T17 provider harnesses
exercise the existing synchronous signup transports.
