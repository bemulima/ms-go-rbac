package domain

const MCPMentorCohortRespondScope = "mentor:cohorts:respond"
const MCPMentorCohortRespondAction = "mcp.mentor.cohorts.respond"

const MCPMentorStudentFeedbackScope = "mentor:students:feedback"
const MCPMentorStudentFeedbackAction = "mcp.mentor.students.feedback"

func MCPMentorManagementAction(scope string) string {
	switch scope {
	case "mentor:profile:write":
		return "mcp.mentor.profile.write"
	case "mentor:offers:write":
		return "mcp.mentor.offers.write"
	case "mentor:students:write":
		return "mcp.mentor.students.write"
	case "mentor:cohorts:write":
		return "mcp.mentor.cohorts.write"
	case "mentor:schedule:write":
		return "mcp.mentor.schedule.write"
	case "mentor:offers:publish":
		return "mcp.mentor.offers.publish"
	case "mentor:schedule:cancel":
		return "mcp.mentor.schedule.cancel"
	}
	return ""
}
