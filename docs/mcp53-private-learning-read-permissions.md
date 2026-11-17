# MCP-53 — private Student graph and lesson permissions (source only)

The read-only MCP scope grammar adds two **independent** default-role checks:

| Exact OAuth scope | Exact RBAC default Student permission | Resource kind |
| --- | --- | --- |
| `knowledge:read` | `mcp.knowledge.read` | empty |
| `lessons:read` | `mcp.lessons.read` | empty |

The evaluator still reads the current canonical default Student role,
performs one `HasDefaultPermission` check for each requested scope, signs
only the allowed subset and denies all requested scopes on an outage or
ambiguous role. `courses:read` never implies these permissions; neither
private permission implies the other. No permission or role-permission link
is created, and no migration or operator bootstrap is executed.

The full read-only grammar limit grows from four to six; the combined
read/write grammar from eight to ten. Unknown, unordered, repeated,
cross-student or forged JWT claims remain denied. Runtime is unchanged and
no MCP permission grants are activated.

After scoped Mac/owner acceptance, an operator must explicitly provision
the two permission rows and Student default-role links, and Auth must enable
the separate private-content scope ceiling. Source-only mapping alone is
never an ACL.
