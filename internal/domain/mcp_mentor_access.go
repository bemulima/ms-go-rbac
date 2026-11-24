package domain

import "context"

const (
	MCPMentorAccessSubject     = "rbac.checkMCPMentorAccess"
	MCPMentorProfileScope      = "mentor:profile:read"
	MCPMentorProfilePermission = "mcp.mentor.profile.read"
	MCPMentorProofAudience     = "ms-go-rbac-mcp-mentor"
	MCPMentorProofPurpose      = "AUTH_RBAC_MCP_MENTOR_ACCESS_V1"
	MCPMentorDecisionAudience  = "ms-go-auth-mcp-mentor-decision"
	MCPMentorDecisionPurpose   = "RBAC_AUTH_MCP_MENTOR_ACCESS_V1"
)

// This is a point-in-time role and explicit permission observation, not an
// OAuth consent or domain-owner approval. No Student or Admin fallback exists.
type MCPMentorAccess struct{ Active, Allowed bool }
type MCPMentorAccessReader interface {
	ReadMCPMentorAccess(context.Context, string) (MCPMentorAccess, error)
}
type MCPMentorProof struct {
	Subject, JWTID, Digest string
	ExpiresAt              int64
}
type MCPMentorProofVerifier interface {
	VerifyMCPMentorProof(context.Context, string) (MCPMentorProof, error)
}
type MCPMentorDecisionSigner interface {
	SignMCPMentorDecision(MCPMentorProof, MCPMentorAccess) (string, error)
}
