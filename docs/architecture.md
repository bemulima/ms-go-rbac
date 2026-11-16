# Architecture

The active service exposes read-only HTTP principal/admin lookups and three Core NATS RPC handlers backed by PostgreSQL repositories: signed student role assignment, role checking, and the Auth-proof-bound `knowledge_graph.review` permission lookup. `cmd/ms-rbac-service` is the composition root. Inbound HTTP is separated into API, admin, and private contours under `internal/transport/http`; inbound Core NATS RPC handlers are under `internal/transport/message`; PostgreSQL and NATS clients are outbound infrastructure. Use cases depend on domain repository ports, not PostgreSQL implementations. It does not currently expose a complete policy-decision endpoint.

A PDP engine and PostgreSQL PDP repository exist, including superadmin, override-specificity, scoped-role, and permission matching logic. They are not wired into bootstrap, and the repository methods take context while the domain Repository interface does not. Therefore former wiki claims that PDP and overrides are fully active are intent/historical documentation, not current runtime behavior.

The HTTP router denies all non-read methods before dispatch. Read routes retain their legacy authentication boundary. API and admin reads remain directly callable on the service network; this patch does not add a general read-authorization policy. Legacy CRUD handlers remain behind unconditional mutation denial.

The NATS role assignment consumer now admits only a dedicated Auth Ed25519-signed canonical student signup proof. Cryptographic verification and fixed operation/target/role/scope binding precede all receipt lookup or role access. The signup application calls a separate transactional repository that inserts student only into the exact default tuple, refuses a different existing role, and atomically records an immutable issuer/operation receipt. Replay still authenticates a fresh proof and performs no writes for the same binding. The generic principal-role usecase remains a legacy internal API, but NATS does not call its unsigned mutation path.

The reviewer permission RPC accepts only a short-lived Auth RS256 proof. RBAC pins the configured Auth issuer, a fixed audience, proof purpose/type, exact permission, subject/JTI shape, and lifetime before deriving the principal from `sub`. It evaluates only the unique canonical default-scope role and returns false for missing grants; ambiguous role bindings or dependency failures deny the lookup.

Operator-only initial grants use PrincipalRoleUsecase.Bootstrap and the existing assignment persistence helper, committing an immutable receipt with the grant. See operator-bootstrap.md. No HTTP/NATS administrative grant is composed.

Mentor's dedicated source-only mutation follows domain/usecase/outbound-adapter
boundaries: a fresh Auth proof enters MentorRoleMutation; its atomic store
rechecks current canonical Admin and writes only the dedicated Mentor scope,
immutable receipt and terminal fence. See mentor-role-owner.md. The usecase,
store and prior signed lookup providers are not wired into active bootstrap.
No public mutation route, active PDP path or legacy role-management authority
is added by these files.

The source-only `rbac.applyMentorRole.v1` handler accepts only the exact Auth
proof envelope and calls this concrete mutation use case under a bounded
context. It exposes neither historical receipt nor role state; an unsigned ACK
never replaces signed readback. Fixed error categories use exact owner
sentinels, with mixed/wrapped failures kept unavailable. It has no subscription
or bootstrap registration; the atomic store and migrations are unchanged.

The signed Mentor scoped-role readback uses dedicated service proof admission,
a narrow usecase, a coherent read-only PostgreSQL snapshot and nonce/digest-bound
reply signing. It does not recheck the historical Admin or mutate roles.
Provider and consumer remain unmounted; see mentor-scoped-role-readback.md.

An explicit default-off source constructor now assembles the three existing
Mentor consumers in `cmd/ms-rbac-service`, using an already-owned pool and
dedicated validated keys. Its fixed dispatcher preserves the actual subject;
it does not connect, subscribe, listen or change active bootstrap. See
[Mentor owner composition](mentor-owner-composition.md). Construction tests
prove wiring and denial paths, not SQL or mounted owner acceptance.
