package domain

import "context"

// These are distinct from the reviewer and MCP Student role-only contracts.
// They are dormant: no subject, signer, or verifier is wired into bootstrap.
const (
	MCPStudentScopeProofAudience          = "ms-go-rbac-mcp-student-scopes"
	MCPStudentScopeProofType              = "mcp_student_scope_check"
	MCPStudentScopeProofPurpose           = "AUTH_RBAC_MCP_STUDENT_SCOPES_V1"
	MCPStudentScopeProofMaxAgeSeconds     = 30
	MCPStudentScopeProofFutureSkewSeconds = 5
	MCPStudentScopeDecisionIssuer         = "ms-go-rbac"
	MCPStudentScopeDecisionAudience       = "ms-go-auth-mcp-student-scopes-decision"
	MCPStudentScopeDecisionType           = "mcp_student_scopes_decision"
	MCPStudentScopeDecisionPurpose        = "RBAC_AUTH_MCP_STUDENT_SCOPES_DECISION_V1"
	MCPStudentScopeDecisionTTLSeconds     = 15
)

// MCPStudentScopeProof is recovered only from a verified Auth RS256 proof.
// ProofDigest is the lowercase SHA-256 of the exact raw JWT, not a claim.
type MCPStudentScopeProof struct {
	Subject     string
	JWTID       string
	Requested   []string
	ProofDigest string
}

type MCPStudentScopeProofVerifier interface {
	VerifyMCPStudentScopeProof(context.Context, string) (MCPStudentScopeProof, error)
}

// A decision signer binds the exact requested and explicitly allowed scopes
// to the verified proof. Neither a role-only JWT nor unsigned subset is valid.
type MCPStudentScopeDecisionSigner interface {
	SignMCPStudentScopeDecision(MCPStudentScopeProof, string, []string) (string, error)
}
