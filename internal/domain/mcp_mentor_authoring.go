package domain

func MCPMentorAuthoringAction(scope string) string {
	switch scope {
	case "mentor:courses:write":
		return "mcp.mentor.courses.write"
	case "mentor:tasks:write":
		return "mcp.mentor.tasks.write"
	case "mentor:courses:publish":
		return "mcp.mentor.courses.publish"
	case "mentor:tasks:publish":
		return "mcp.mentor.tasks.publish"
	}
	return ""
}
