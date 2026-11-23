package domain

import "context"

const (
	MCPStudentRole                       = "student"
	MCPStudentRoleProofAudience          = "ms-go-rbac-mcp-student-role"
	MCPStudentRoleProofType              = "mcp_student_role_check"
	MCPStudentRoleProofPurpose           = "AUTH_RBAC_MCP_STUDENT_ROLE_V1"
	MCPStudentRoleProofMaxAgeSeconds     = 30
	MCPStudentRoleProofFutureSkewSeconds = 5
	MCPStudentRoleDecisionIssuer         = "ms-go-rbac"
	MCPStudentRoleDecisionAudience       = "ms-go-auth-mcp-student-role-decision"
	MCPStudentRoleDecisionType           = "mcp_student_role_decision"
	MCPStudentRoleDecisionPurpose        = "RBAC_AUTH_MCP_STUDENT_ROLE_DECISION_V1"
	MCPStudentRoleDecisionTTLSeconds     = 15
	MCPStudentRoleDecisionMaxAgeSeconds  = 30
)

// MCPStudentRoleProof is recovered only from an authenticated, purpose-bound
// Auth RS256 proof. This carries no OAuth scopes or client-supplied role.
type MCPStudentRoleProof struct {
	Subject string
	JWTID   string
}

// MCPStudentRoleProofVerifier must reject unsigned, stale or wrong-purpose
// assertions before RBAC reads any role assignment.
type MCPStudentRoleProofVerifier interface {
	VerifyMCPStudentRoleProof(context.Context, string) (MCPStudentRoleProof, error)
}

// MCPStudentRoleDecisionSigner signs the fresh fixed-role decision with an
// exact request digest and request JTI. An unsigned boolean is never authority.
type MCPStudentRoleDecisionSigner interface {
	SignMCPStudentRoleDecision(MCPStudentRoleProof, string, bool) (string, error)
}
