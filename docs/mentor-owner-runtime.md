# Explicitly enabled Mentor owner wiring

Parent: `bemulima/learning-platform-business#27`, MENT-01A.
Status: **source-only executable wiring; disabled by default; SQL, broker,
live-session, migration and Gherkin acceptance NOT_RUN**.

`bootstrap` optionally invokes the existing
[`NewMentorOwnerComposition`](mentor-owner-composition.md). Domain rules,
claim parsers and real PostgreSQL repositories remain unchanged. No new public
role-management API, generic assignment fallback or background grant exists.
Student signup, reviewer handling, role reads and HTTP mutation denial retain
their existing semantics.

## Explicit configuration

`RBAC_MENTOR_OWNER_ENABLED` accepts only `true`, `false` or absent/empty. Only
exact `true` enables the path; other nonempty spellings are errors. Disabled
mode ignores all Mentor settings and opens no additional connection or subscription.

Enabled preflight runs before any database or broker connection:

| Setting | Requirement |
| --- | --- |
| `RBAC_MENTOR_NATS_URL` | One `tls://host:port`; no embedded credentials, path, query, fragment or server list |
| `RBAC_MENTOR_NATS_CREDENTIALS_FILE` | Absolute readable regular non-symlink file owned by current UID, no group/other permissions, <=32 KiB, matched NATS user JWT subject and user seed |
| `RBAC_MENTOR_NATS_CA_FILE` | Optional absolute regular non-symlink CA PEM, <=1 MiB; omission uses system roots, never insecure verification |
| `RBAC_MENTOR_AUTH_ADMIN_LOOKUP_PUBLIC_KEY` | Dedicated Auth canonical-Admin lookup RSA public PEM |
| `RBAC_MENTOR_AUTH_ROLE_DECISION_PUBLIC_KEY` | Dedicated Auth role-decision RSA public PEM |
| `RBAC_MENTOR_READBACK_REQUEST_PUBLIC_KEY` | Dedicated Mentor service readback RSA public PEM |
| `RBAC_MENTOR_ADMIN_DECISION_PRIVATE_KEY` / `RBAC_MENTOR_ADMIN_DECISION_PUBLIC_KEY` | Matched RBAC Admin-response RSA pair |
| `RBAC_MENTOR_READBACK_DECISION_PRIVATE_KEY` / `RBAC_MENTOR_READBACK_DECISION_PUBLIC_KEY` | Matched RBAC scoped-readback RSA pair |

The five purpose keys must be RSA >=2048 with distinct moduli. PEM aliases and
different exponents cannot hide reuse. Enabled preflight also rejects malformed
or reused configured legacy `AUTH_JWT_PUBLIC_KEY` and
`RBAC_REVIEWER_PERMISSION_DECISION_PRIVATE_KEY` RSA material. No key, account,
credential, alias or grant is automatically generated or provisioned.

Nonblocking/no-follow opens reject special files and symlink substitutions. The
credential is read once into a bounded snapshot. Pinned `nats.go` v1.33
has no `UserCredentialBytes`; its native `UserJWTAndSeed` callbacks are built
from this snapshot after parsing a user seed. A fixed non-secret challenge is
signed and verified against the JWT `sub` user NKey. Callbacks never reread or
expand the path. Temporary byte buffers are wiped; native callbacks retain
credentials for the connection lifetime. This proves only **local pair
consistency**, not issuer, expiry, account or ACL admission: those remain the
authenticated broker's responsibility. No credential is printed or persisted.

## Dedicated transport and lifecycle

Legacy `NATS_URL` and its connector are not reused or reconfigured. The dedicated
connection requires verified TLS >=1.2 with the original hostname as ServerName
and a broker reporting authentication required. There is no anonymous, insecure,
URL-credential or legacy fallback. Reconnect is disabled. Since v1.33 can expand
its initial server list from INFO, a custom dialer admits only `tcp` and the
configured host:port; discovery aliases are rejected before dialing. DNS for
that hostname uses the normal bounded dialer. Startup has a context of at most
five seconds; a single-attempt dial guard prevents repeated attempts and remains
armed through INFO/TLS/authentication/flush cancellation. No automatic retry or
reconnect buffering is permitted, and the flusher is bounded to five seconds.
Verified TLS provenance is recorded from `tls.Config.VerifyConnection`, not
from the pinned client's unsynchronized `TLSConnectionState` status read.

Exactly three existing consumers use queue group `ms-go-rbac`:

- `rbac.checkMentorCanonicalAdmin.v1`
- `rbac.applyMentorRole.v1`
- `rbac.checkRoleScoped.v1`

Callbacks check the exact delivered subject and pass original `msg.Subject`
and `msg.Data` into the actual composition. Caller headers cannot replace
authority. Only canonical ASCII `_INBOX.*` replies up to 256 bytes are accepted,
without wildcards, whitespace or empty tokens; malformed inboxes are dropped.
Inbound and outbound envelopes are capped at 16 KiB and must be UTF-8. Native
subscription queues are bounded to 128 pending messages / 1 MiB; failure to set
limits unsubscribes and aborts startup. The production parsers,
usecases and stores remain in the path. Mutation ACK is still not permission;
failed lookups return generic unavailable, never fabricated signed DENY.

Admission opens only after all subscriptions and the broker flush succeed.
Subscription, flush and known asynchronous broker errors abort startup and close
the dedicated connection. Later permission, publish or disconnect failures stop
admission, cancel owner contexts and notify `main` to shut down nonzero. No
partial subset remains ready. These source checks do not prove real broker ACLs.

Shutdown closes admission, drains the dedicated connection and waits for its
closed callback and admitted workers before closing the pool. The earlier caller
deadline or five seconds bounds drain. Error/timeout cancels work and force-closes
transport; it never claims a mutation rolled back. PostgreSQL operation/rollback
cleanup keeps its existing bounds. HTTP/listener failures and the legacy connection
are also cleaned up before pool close, without changing legacy subscription semantics.

## Verification boundary

Targeted `mentor-owner-runtime-*` commands use an injected broker transport,
actual cryptographic consumers, production repository methods over controlled
pool fixtures, and ephemeral test-only credentials no real broker issued or
received. They cover opt-in, preflight denials, frozen credentials, endpoint pinning,
actual subjects, atomic readiness, error sanitization and bounded cleanup.
They never connect, listen, start services, execute SQL/migrations or provision
runtime credentials. The broad suite is not repeated for this source vertical.

Before actual opt-in, separately accept migration 005 and durable SQL behavior,
current canonical Admin/Student preservation, dedicated key custody and broker
ACLs, matched Auth/Mentor configuration and live-session integration. The prior
PostgreSQL permission failure remains a hard stop: no alternate socket/listener
or elevated runtime workaround is introduced. Executable business Gherkin and
MENT-00 relocation remain in `learning-platform-verification`.
