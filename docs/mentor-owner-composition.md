# Default-off Mentor owner composition

Parent: `bemulima/learning-platform-business#27`, MENT-01A.
Status: **source-only construction; unmounted; SQL/runtime/Gherkin NOT_RUN**.

`cmd/ms-rbac-service/mentor_composition.go` adds
`NewMentorOwnerComposition(config, pool)` without invoking it from active
`bootstrap` or `main`. This is not service activation. The returned dispatcher
only exposes these fixed, existing owner contracts:

| Actual subject | Concrete existing composition |
| --- | --- |
| `rbac.checkMentorCanonicalAdmin.v1` | Auth Admin lookup verifier → `PrincipalRoleRepository.GetDefaultRole` through `MentorCanonicalAdminLookup` → dedicated Admin decision signer |
| `rbac.applyMentorRole.v1` | Auth role proof verifier → `MentorRoleMutation` → atomic `MentorRoleStore` → existing strict mutation consumer |
| `rbac.checkRoleScoped.v1` | Mentor readback proof verifier → `MentorRoleReadbackLookup` → `MentorRoleReader` → dedicated readback decision signer |

The existing owner contracts remain authoritative: [Admin lookup](mentor-admin-lookup.md),
[mutation RPC](../.ai/contracts/mentor-role-mutation-rpc-v1.md),
[atomic store](mentor-role-owner.md), and [readback](mentor-scoped-role-readback.md).
There is no new claim schema, SQL query, migration, role planner or permission.

## Configuration and lifecycle

`MentorOwnerCompositionConfig.Enabled` defaults to false. Disabled construction
returns `nil, nil`, with no handler construction, key parsing or pool calls.
The nil dispatcher's `Subjects()` is empty and `Handle` fails closed.

Enabled construction requires an already-owned non-nil `MentorOwnerPool`.
The port comprises existing pgx `Begin`, `BeginTx` and `QueryRow` methods;
`*pgxpool.Pool` implements it. Typed-nil pool values are rejected. This code
never opens, pings, migrates, closes or takes lifecycle ownership of a pool.
It cannot establish that a supplied pool is connected or that SQL is qualified.

All configuration is passed explicitly; no environment or key files are read.
Required keys are:

- `AuthAdminLookupPublicKeyPEM`
- `AuthRoleDecisionPublicKeyPEM`
- `MentorReadbackPublicKeyPEM`
- `AdminDecisionPrivateKeyPEM` and matching `AdminDecisionPublicKeyPEM`
- `ReadbackDecisionPrivateKeyPEM` and matching `ReadbackDecisionPublicKeyPEM`

Each is one supported RSA PEM, with at least 2048 bits. Both owner reply pairs
must match. All five purpose keys must have different RSA moduli: another PEM
encoding or exponent cannot hide key reuse. Configuration failures return only
`ErrAuthorityUnavailable` and no partially usable dispatcher. Existing client
factories remain responsible for their purpose-specific crypto. No runtime
credentials are generated, provisioned, printed or selected automatically.
An operator still has to prove these explicitly supplied keys are not reused
by unrelated legacy JWT/signup/reviewer configuration, which this constructor
does not read.

`Subjects()` returns a fresh list, not a mutable handler map. `Handle(ctx,
actualSubject, body)` passes the actual subject and original body unchanged to
the selected existing consumer. Unknown subjects, aliases, wildcards, nil or
cancelled context fail closed. The dispatcher bounds the operation context to
five seconds and preserves earlier deadlines. Existing transaction cleanup may
extend total return time; cancellation is not proof that a mutation rolled back.

Future separately authorised mounting must use the existing service queue group
and pass the actual received `msg.Subject`, not the subscription constant or
caller headers. This source constructor never calls Connect, Subscribe or
Listen and does not provide a broker authentication or ACL fallback.

## Narrow verification boundary

The new catalogued commands are `mentor-owner-composition-tests` and
`mentor-owner-composition-race`. They run only `TestMentorOwnerComposition*`
in `./cmd/ms-rbac-service`, not the existing broad cryptographic suites.

Tests use ephemeral in-memory keys, the actual verifiers/usecases/repositories/
consumers and a minimal pool protocol fixture. The canonical-Admin path reaches
the real unique-default query and real reply signer. Valid mutation/readback
proofs reach their concrete adapters' distinct transaction modes, then the
fixture deliberately rejects `BeginTx`; no successful SQL/grant/readback is
invented. Disabled and invalid configurations make no pool call. No listener,
broker, database, migration or real business scenario is started.

Execution is deferred until the coordinated source vertical is ready. Recording
or compiling these tests alone is not a PASS result. SQL permission remains a
stop condition; no socket workaround, elevated retry or runtime activation is
authorised by this source change. Real owner/SQL/Gateway acceptance and original
MENT-001 UI/private-capability scenarios remain separate outstanding gates.
