package domain

import "context"

const (
	MentorRoleReadbackSubject                = "rbac.checkRoleScoped.v1"
	MentorRoleReadbackIssuer                 = "ms-go-mentor"
	MentorRoleReadbackAudience               = "ms-go-rbac-mentor-role-readback"
	MentorRoleReadbackType                   = "mentor_role_readback_check"
	MentorRoleReadbackPurpose                = "MENTOR_RBAC_SCOPED_ROLE_READBACK_V1"
	MentorRoleReadbackDecisionIssuer         = "ms-go-rbac"
	MentorRoleReadbackDecisionAudience       = "ms-go-mentor-scoped-role-readback"
	MentorRoleReadbackDecisionType           = "mentor_role_readback_decision"
	MentorRoleReadbackDecisionPurpose        = "RBAC_MENTOR_SCOPED_ROLE_READBACK_DECISION_V1"
	MentorRoleReadbackMaxTTL                 = 30
	MentorRoleReadbackDecisionMaxTTL         = 15
	MentorRoleReadbackFutureSkew             = 5
	MentorRoleReadbackMaxTimestamp     int64 = 1<<53 - 1
	MentorRoleReadbackMaxTokenBytes          = 8192
	MentorRoleReadbackMaxEnvelopeBytes       = 16384
)

// MentorRoleReadbackProof authenticates a dedicated Mentor service read, not
// the original Admin's current session and not a new role mutation authority.
type MentorRoleReadbackProof struct {
	Command     MentorRoleCommand
	Subject     string
	JWTID       string
	ProofDigest string
	IssuedAt    int64
	ExpiresAt   int64
}

// MentorRoleReadbackResult confirms only the exact requested current command.
// Unconfirmed must not reveal an unrelated or superseding command's state.
type MentorRoleReadbackResult struct {
	Confirmed bool
	Active    bool
}

type MentorRoleReadbackReader interface {
	ReadMentorRole(context.Context, MentorRoleCommand) (MentorRoleReadbackResult, error)
}

type MentorRoleReadbackChecker interface {
	Check(context.Context, MentorRoleCommand) (MentorRoleReadbackResult, error)
}

type MentorRoleReadbackProofVerifier interface {
	VerifyMentorRoleReadbackProof(context.Context, string, string) (MentorRoleReadbackProof, error)
}

type MentorRoleReadbackDecisionSigner interface {
	Sign(context.Context, MentorRoleReadbackProof, MentorRoleReadbackResult) (string, error)
}

// ValidMentorRoleReadbackResult checks shape, not authenticity or freshness.
func ValidMentorRoleReadbackResult(command MentorRoleCommand, result MentorRoleReadbackResult) bool {
	if !ValidMentorRoleCommand(command) {
		return false
	}
	if !result.Confirmed {
		return !result.Active
	}
	return result.Active == (command.Decision == MentorRoleDecisionApprove)
}
