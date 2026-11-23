package domain

import "context"

const (
	MentorCanonicalAdminSubject             = "rbac.checkMentorCanonicalAdmin.v1"
	MentorAdminLookupIssuer                 = "ms-go-auth"
	MentorAdminLookupAudience               = "ms-go-rbac-mentor-canonical-admin"
	MentorAdminLookupType                   = "mentor_canonical_admin_check"
	MentorAdminLookupPurpose                = "AUTH_RBAC_MENTOR_CANONICAL_ADMIN_LOOKUP_V1"
	MentorAdminDecisionIssuer               = "ms-go-rbac"
	MentorAdminDecisionAudience             = "ms-go-auth-mentor-canonical-admin-decision"
	MentorAdminDecisionType                 = "mentor_canonical_admin_decision"
	MentorAdminDecisionPurpose              = "RBAC_AUTH_MENTOR_CANONICAL_ADMIN_DECISION_V1"
	MentorAdminDecisionMaxTTL               = 15
	MentorAdminLookupMaxTTL                 = 30
	MentorAdminLookupFutureSkew             = 5
	MentorAdminLookupMaxTimestamp     int64 = 1<<53 - 1
	MentorAdminLookupMaxTokenBytes          = 8192
	MentorAdminLookupMaxEnvelopeBytes       = 16384
)

// MentorAdminLookupProof is recovered only from a verified dedicated Auth
// lookup proof. It authenticates the calling service, not a live user session.
type MentorAdminLookupProof struct {
	ActorID     string
	Subject     string
	JWTID       string
	ProofDigest string
	IssuedAt    int64
	ExpiresAt   int64
}

type MentorAdminLookupProofVerifier interface {
	VerifyMentorAdminLookupProof(context.Context, string, string) (MentorAdminLookupProof, error)
}

type MentorCanonicalAdminChecker interface {
	Check(context.Context, string) (bool, error)
}

type MentorCanonicalAdminDecisionSigner interface {
	Sign(context.Context, MentorAdminLookupProof, bool) (string, error)
}

// MentorCanonicalAdminRoleReader is deliberately narrower than the legacy
// principal-role repository. It exposes neither any-scope Get nor mutations.
type MentorCanonicalAdminRoleReader interface {
	GetDefaultRole(context.Context, string) (string, error)
}
