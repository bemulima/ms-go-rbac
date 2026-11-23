# MCP-53: `calendar:read` has no implied Student role grant

The allowed MCP Student **read** grammar now includes `calendar:read` as a
fourth possible scope, sorted first. It maps to the exact RBAC default
Student permission `mcp.calendar.read` with an empty resource kind.

The existing `AllowedMCPStudentReadScopes` lookup remains owner-authoritative:
it reads a fresh, explicit default-role grant for **each** requested scope,
rejects non-Student roles, signs an exact subset and fails closed on metadata
errors. There is no fallback to a generic Student role or a previously signed
decision. No migration seeds this new permission or grants it automatically.

The Calendar read tool is independently opted-in at MCP and Calendar services.
It cannot read Calendar owner raw state, mutate events or contact Mentor.
Runtime permission setup, integration and Gherkin are reserved for the final
local acceptance stage.
