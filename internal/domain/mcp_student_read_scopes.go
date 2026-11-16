package domain

// Pilot MCP Student scopes have no implied grants. Each requires its own
// explicit default-scope RBAC permission and separate Auth/owner checks.
const (
	MCPStudentCalendarReadScope = "calendar:read"
	MCPStudentProfileReadScope  = "profile:read"
	MCPStudentCoursesReadScope  = "courses:read"
	MCPStudentTasksReadScope    = "tasks:read"

	MCPStudentCalendarReadPermission = "mcp.calendar.read"
	MCPStudentProfileReadPermission  = "mcp.profile.read"
	MCPStudentCoursesReadPermission  = "mcp.courses.read"
	MCPStudentTasksReadPermission    = "mcp.tasks.read"

	MCPStudentReadScopeLimit = 4
)

// MCPStudentReadScopePermission accepts only exact read-only pilot scopes.
// Write scopes and all unapproved scopes are never inferred from a role.
func MCPStudentReadScopePermission(scope string) (string, bool) {
	switch scope {
	case MCPStudentCalendarReadScope:
		return MCPStudentCalendarReadPermission, true
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

// ValidMCPStudentReadScopeSet validates the exact canonical pilot set. Both
// Auth proof admission and RBAC policy evaluation use the same ordering rule.
func ValidMCPStudentReadScopeSet(scopes []string) bool {
	if len(scopes) == 0 || len(scopes) > MCPStudentReadScopeLimit {
		return false
	}
	previous := ""
	for _, scope := range scopes {
		if _, ok := MCPStudentReadScopePermission(scope); !ok || scope <= previous {
			return false
		}
		previous = scope
	}
	return true
}

// ValidMCPStudentAllowedReadScopes also permits an explicitly evaluated
// empty (but non-nil) subset. Nil means no authorization evaluation occurred.
func ValidMCPStudentAllowedReadScopes(requested, allowed []string) bool {
	if !ValidMCPStudentReadScopeSet(requested) || allowed == nil || len(allowed) > len(requested) {
		return false
	}
	requestedIndex := 0
	for _, scope := range allowed {
		for requestedIndex < len(requested) && requested[requestedIndex] < scope {
			requestedIndex++
		}
		if requestedIndex == len(requested) || requested[requestedIndex] != scope {
			return false
		}
		requestedIndex++
	}
	return true
}
