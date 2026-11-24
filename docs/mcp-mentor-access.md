# Signed Mentor MCP access — MENT-07A

`RBAC_MCP_MENTOR_ENABLED=false` by default. Enabling it registers the read-only
Core NATS request/reply subject `rbac.checkMCPMentorAccess` in queue
`ms-go-rbac`. It never adds an HTTP mutation, grants a role, creates consent or
authorizes domain objects. Source implementation and tests do not establish
live SQL/broker acceptance or authorize activation.

## Exact authority

The only supported scope is `mentor:profile:read`, mapped to
`mcp.mentor.profile.read` with empty permission resource kind and canonical
zero resource ID. Permission requires an explicit `role_permission` assignment
to the marker-owned `mentor` role. Migration 006 creates only owned permission
metadata, no assignment or principal grant. Administrative APIs remain denied.
Client registration, consent and access tokens belong to Auth; approved Mentor
business state and own-profile object access belong to Mentor.

The reader uses one repeatable-read, read-only transaction. It validates the
existing `mentor_role_scope` role/service marker, current target fence, exact
immutable command receipt, matching application/target indexes and physical
assignment at the exact `user`/zero-tenant/`ms-go-mentor`/`global`/zero-resource
tuple. It then reads the explicit marker-owned profile permission in that same
snapshot. Current suspension or authoritative absence returns inactive/denied.
Metadata corruption, a dangling receipt, assignment drift, cancellation or
database failure yields no signed semantic decision. Historical approval,
generic role lookup, canonical default Student, Admin/superadmin and unscoped
fallbacks provide no authority.

This is a point-in-time observation. It does not lock revocation across services.
Auth obtains a new decision for every authorization, token exchange and MCP
verification, independently checks current Mentor approval, then rereads its
own consent/client/account state. Mentor repeats its owner checks for the read.

## Signed contract

The request envelope contains exactly `proof`. No raw actor, scope or role is
accepted beside it. The Auth-owned proof uses dedicated RS256/JWT signing,
the exact configured HTTPS `/mentor` issuer, audience `ms-go-rbac-mcp-mentor`,
purpose `AUTH_RBAC_MCP_MENTOR_ACCESS_V 1`, persona `MENTOR`, fixed profile scope,
canonical nonzero UUID `sub`/`jti` and integer `iat`/`exp`. Lifetime is at most 15
seconds; future issue times are denied. Student, owner-approval and role-mutation
proofs cannot substitute for this proof.

Success is exactly `{decision_jwt}`. The signed reply fields are:

| Field | Binding |
| --- | --- |
| `iss` | `ms-go-rbac` |
| `aud` | `ms-go-auth-mcp-mentor-decision` |
| `sub`, `persona`, `scope` | Verified request subject, `MENTOR`, `mentor:profile:read` |
| `purpose` | `RBAC_AUTH_MCP_MENTOR_ACCESS_V 1` |
| `active` | Exact current approved scoped role. |
| `allowed` | Role active and explicit profile permission present. |
| `request_jti`, `request_digest` | Verified request nonce and lowercase SHA-256 of the exact compact proof. |
| `jti` | Fresh canonical nonzero UUID. |
| `iat`, `exp` | Integer seconds, maximum 15-second reply, expiry capped to request. |

The JOSE header has exactly `alg=RS256`, `typ=JWT`. Claims reject duplicates,
unknown/case/escaped property aliases, nulls, malformed types, invalid UTF-8 and
trailing JSON. `allowed=true` with `active=false` is invalid. Denied role or
permission still receives a signed bound negative result; dependency and proof
failures expose only a fixed error envelope. Auth verifies the independent RBAC
key, full binding and one-use reply JTI before considering the result.

## Configuration and rollout constraints

Required enabled settings are `RBAC_MCP_MENTOR_AUTH_ISSUER`,
`RBAC_MCP_MENTOR_AUTH_PUBLIC_KEY`, `RBAC_MCP_MENTOR_DECISION_PRIVATE_KEY` and the
existing `NATS_URL`. Keys must use distinct RSA moduli, including when exponents
differ, and must not reuse configured web/Student/reviewer/Mentor-owner keys.
The enabled trust configuration is checked before database or broker connection.
The fixed queue/subject preserves existing Core NATS semantics. Deployment must
provide verified transport and subject ACLs; source-only test brokers/fixtures
are never fallback authority.

The canonical owner migration runner discovers additive 006 after 005. The
existing Student-only disposable migration profile is intentionally unchanged;
it does not prove Mentor schema readiness. Rollback of 006 requires the exact
owned permission row and refuses any role, service or principal-override
assignment to that permission. Mentor role receipts and suspension tombstones
remain governed by 005 and are unchanged.

Source tests exercise actual signature verification/signing, purpose/nonce/
digest/time fences, permission-off and suspension results, metadata/receipt/
physical corruption and same-snapshot transaction protocol. These protocol
fixtures do not execute SQL. Actual PostgreSQL migration, rollback and
concurrency acceptance and full cross-owner deployment remain NOT_RUN here.
