package domain

const MCPMentorCohortRespondScope = "mentor:cohorts:respond"
const MCPMentorCohortRespondAction = "mcp.mentor.cohorts.respond"

const MCPMentorDialogWriteScope = "mentor:dialogs:write"
const MCPMentorDialogWriteAction = "mcp.mentor.dialogs.write"

const MCPMentorStudentFeedbackScope = "mentor:students:feedback"
const MCPMentorStudentFeedbackAction = "mcp.mentor.students.feedback"

func MCPMentorTaskAssignmentAction(scope string) string {
	switch scope {
	case "mentor:students:assign":
		return "mcp.mentor.students.assign"
	case "mentor:cohorts:assign":
		return "mcp.mentor.cohorts.assign"
	}
	return ""
}

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
