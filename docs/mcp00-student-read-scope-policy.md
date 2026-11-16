# MCP-00C3D3: pilot Student read-scope RBAC policy (dormant)

Parent: [MCP Epic #53](https://github.com/bemulima/learning-platform-business/issues/53).

This source-only policy does **not** enable an MCP server, OAuth exchange,
NATS subscription, permission grant, or object read. It extends the role-only
MCP-00C3D1 candidate with a separate per-scope evaluator
`PrincipalPermissionUsecase.AllowedMCPStudentReadScopes`.

| Exact requested scope | Exact default RBAC permission action | Resource kind |
| --- | --- | --- |
| `profile:read` | `mcp.profile.read` | empty |
| `courses:read` | `mcp.courses.read` | empty |
| `tasks:read` | `mcp.tasks.read` | empty |

The existing PostgreSQL `HasDefaultPermission` query requires an exact link
from the Student role to each permission at the canonical **zero resource ID**.
Neither the Student role nor an unrelated course/task permission implies any
MCP scope. There is no implicit admin override and this change seeds **zero**
permission rows or role-permission links. An absent grant is DENY. Revocation
affects the next evaluation, without a cached scope set.

The evaluator accepts only a lowercase canonical nonzero principal UUID and a
nonempty, strictly lexicographically sorted, duplicate-free set of one to three
exact pilot scopes. Unknown scopes, write scopes, prefixes, malformed requests,
or a canceled context are denied before hitting the permission store. It reads
the unique current canonical default user/global role via `GetDefaultRole`;
only exactly `student` proceeds to per-scope permission lookup. Other roles,
including `admin`, or non-default Student assignments grant no scopes.
Ambiguous roles, storage errors, and canceled evaluations produce **no**
partial successful scope set. A successful evaluation returns only the
explicitly granted subset of the requested scopes.

The evaluator is **not** a credential or externally callable RPC. It cannot
populate `RBACStudentScopes` in Auth today. A separate future change must:

1. Define and sign an Auth-to-RBAC scope request and a fresh, replay-bound
   RBAC-to-Auth decision; the MCP-00C3D1 **role-only** JWT is insufficient.
2. Have Auth validate the MCP client, Student session, consent snapshot,
   platform policy, and signed RBAC decision before composing token scopes.
3. Require the domain owner of each object to authorize the actual profile,
   course, or task read; RBAC role/scope permissions never replace object ACL.
4. Keep all write scopes and other proposed MCP scopes denied until separately
   designed, approved, implemented, and verified.

This is an incremental source contract, not integration or runtime evidence.
