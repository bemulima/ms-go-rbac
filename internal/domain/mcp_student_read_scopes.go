package domain

// Pilot MCP Student scopes have no implied grants. Each requires its own
// explicit default-scope RBAC permission and separate Auth/owner checks.
const (
	MCPStudentProfileReadScope = "profile:read"
	MCPStudentCoursesReadScope = "courses:read"
	MCPStudentTasksReadScope   = "tasks:read"

	MCPStudentProfileReadPermission = "mcp.profile.read"
	MCPStudentCoursesReadPermission = "mcp.courses.read"
	MCPStudentTasksReadPermission   = "mcp.tasks.read"

	MCPStudentReadScopeLimit = 3
)

// MCPStudentReadScopePermission accepts only exact read-only pilot scopes.
// Write scopes and all unapproved scopes are never inferred from a role.
func MCPStudentReadScopePermission(scope string) (string, bool) {
	switch scope {
	case MCPStudentProfileReadScope:
		return MCPStudentProfileReadPermission, true
	case MCPStudentCoursesReadScope:
		return MCPStudentCoursesReadPermission, true
	case MCPStudentTasksReadScope:
		return MCPStudentTasksReadPermission, true
	default:
		return "", false
	}
}
