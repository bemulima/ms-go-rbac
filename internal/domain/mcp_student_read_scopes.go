package domain

// Pilot MCP Student scopes have no implied grants. Each requires its own
// explicit default-scope RBAC permission and separate Auth/owner checks.
const (
	MCPStudentCalendarReadScope  = "calendar:read"
	MCPStudentProfileReadScope   = "profile:read"
	MCPStudentCoursesReadScope   = "courses:read"
	MCPStudentKnowledgeReadScope = "knowledge:read"
	MCPStudentLessonsReadScope   = "lessons:read"
	MCPStudentTasksReadScope     = "tasks:read"

	MCPStudentInstancesStartScope   = "instances:start"
	MCPStudentWorkspaceWriteScope   = "workspace:write"
	MCPStudentSubmissionsWriteScope = "submissions:write"
	MCPStudentValidationRunScope    = "validation:run"

	MCPStudentCalendarReadPermission  = "mcp.calendar.read"
	MCPStudentProfileReadPermission   = "mcp.profile.read"
	MCPStudentCoursesReadPermission   = "mcp.courses.read"
	MCPStudentKnowledgeReadPermission = "mcp.knowledge.read"
	MCPStudentLessonsReadPermission   = "mcp.lessons.read"
	MCPStudentTasksReadPermission     = "mcp.tasks.read"

	MCPStudentInstancesStartPermission   = "mcp.instances.start"
	MCPStudentWorkspaceWritePermission   = "mcp.workspace.write"
	MCPStudentSubmissionsWritePermission = "mcp.submissions.write"
	MCPStudentValidationRunPermission    = "mcp.validation.run"

	MCPStudentReadScopeLimit = 6
	MCPStudentAllScopeLimit  = 10
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
	case MCPStudentKnowledgeReadScope:
		return MCPStudentKnowledgeReadPermission, true
	case MCPStudentLessonsReadScope:
		return MCPStudentLessonsReadPermission, true
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

// MCPStudentScopePermission supports the four independently consented write
// scopes in addition to V0 reads. RBAC must find an actual default-scope
// permission for each requested scope; this mapping never grants one.
func MCPStudentScopePermission(scope string) (string, bool) {
	if permission, ok := MCPStudentReadScopePermission(scope); ok {
		return permission, true
	}
	switch scope {
	case MCPStudentInstancesStartScope:
		return MCPStudentInstancesStartPermission, true
	case MCPStudentWorkspaceWriteScope:
		return MCPStudentWorkspaceWritePermission, true
	case MCPStudentSubmissionsWriteScope:
		return MCPStudentSubmissionsWritePermission, true
	case MCPStudentValidationRunScope:
		return MCPStudentValidationRunPermission, true
	default:
		return "", false
	}
}

func ValidMCPStudentScopeSet(scopes []string) bool {
	if len(scopes) == 0 || len(scopes) > MCPStudentAllScopeLimit {
		return false
	}
	previous := ""
	for _, scope := range scopes {
		if _, ok := MCPStudentScopePermission(scope); !ok || scope <= previous {
			return false
		}
		previous = scope
	}
	return true
}

func ValidMCPStudentAllowedScopes(requested, allowed []string) bool {
	if !ValidMCPStudentScopeSet(requested) || allowed == nil || len(allowed) > len(requested) {
		return false
	}
	i := 0
	for _, scope := range allowed {
		for i < len(requested) && requested[i] < scope {
			i++
		}
		if i == len(requested) || requested[i] != scope {
			return false
		}
		i++
	}
	return true
}
