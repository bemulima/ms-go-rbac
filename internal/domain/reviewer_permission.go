package domain

import "context"

const (
	KnowledgeGraphReviewPermission           = "knowledge_graph.review"
	ReviewerPermissionProofType              = "knowledge_graph_permission_check"
	ReviewerPermissionProofPurpose           = "AUTH_RBAC_KNOWLEDGE_GRAPH_REVIEW_PERMISSION_V1"
	ReviewerPermissionProofAudience          = "ms-go-rbac-knowledge-review"
	ReviewerPermissionProofMaxAgeSeconds     = 30
	ReviewerPermissionProofFutureSkewSeconds = 5
	ReviewerPermissionDecisionIssuer         = "ms-go-rbac"
	ReviewerPermissionDecisionAudience       = "ms-go-auth-knowledge-review-permission-decision"
	ReviewerPermissionDecisionType           = "knowledge_graph_permission_decision"
	ReviewerPermissionDecisionPurpose        = "RBAC_AUTH_KNOWLEDGE_GRAPH_REVIEW_DECISION_V1"
	ReviewerPermissionDecisionMaxAgeSeconds  = 30
	ReviewerPermissionDecisionTTLSeconds     = 15
)

// ReviewerPermissionProof contains only claims recovered after signature and
// authority validation. Request JTI and subject are copied into the signed
// response so Auth can reject stale or replayed NATS replies.
type ReviewerPermissionProof struct {
	Subject    string
	JWTID      string
	Permission string
}

// ReviewerPermissionProofVerifier authenticates the Auth assertion and returns
// only its verified binding. Callers must never supply the subject separately
// from the proof.
type ReviewerPermissionProofVerifier interface {
	VerifyReviewerPermissionProof(context.Context, string) (ReviewerPermissionProof, error)
}

// ReviewerPermissionDecisionSigner signs the exact permission decision and
// request binding before it leaves the RBAC process.
type ReviewerPermissionDecisionSigner interface {
	Sign(ReviewerPermissionProof, string, bool) (string, error)
}
