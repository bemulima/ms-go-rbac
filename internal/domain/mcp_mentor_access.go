package domain

import "context"

const (
	MCPMentorAccessSubject     = "rbac.checkMCPMentorAccess"
	MCPMentorProfileScope      = "mentor:profile:read"
	MCPMentorProfilePermission = "mcp.mentor.profile.read"
	MCPMentorOffersScope       = "mentor:offers:read"
	MCPMentorOffersPermission  = "mcp.mentor.offers.read"
	MCPMentorProofAudience     = "ms-go-rbac-mcp-mentor"
	MCPMentorProofPurpose      = "AUTH_RBAC_MCP_MENTOR_ACCESS_V1"
	MCPMentorDecisionAudience  = "ms-go-auth-mcp-mentor-decision"
	MCPMentorDecisionPurpose   = "RBAC_AUTH_MCP_MENTOR_ACCESS_V1"
)

func ValidMCPMentorScope(scope string) bool {
	return scope == MCPMentorProfileScope || scope == MCPMentorOffersScope || MCPMentorWorkspaceReadAction(scope) != ""
}

func MCPMentorWorkspaceReadAction(scope string) string {
	switch scope {
	case "mentor:reviews:read":
		return "mcp.mentor.reviews.read"
	case "mentor:students:read":
		return "mcp.mentor.students.read"
	case "mentor:cohorts:read":
		return "mcp.mentor.cohorts.read"
	case "mentor:schedule:read":
		return "mcp.mentor.schedule.read"
	case "mentor:skills:read":
		return "mcp.mentor.skills.read"
	}
	return ""
}

// This is a point-in-time role and explicit permission observation, not an
// OAuth consent or domain-owner approval. No Student or Admin fallback exists.
type MCPMentorAccess struct{ Active, Allowed bool }
type MCPMentorAccessReader interface {
	ReadMCPMentorAccess(context.Context, string, string) (MCPMentorAccess, error)
}
type MCPMentorProof struct {
	Subject, JWTID, Digest, Scope string
	ExpiresAt                     int64
}
type MCPMentorProofVerifier interface {
	VerifyMCPMentorProof(context.Context, string) (MCPMentorProof, error)
}
type MCPMentorDecisionSigner interface {
	SignMCPMentorDecision(MCPMentorProof, MCPMentorAccess) (string, error)
}
