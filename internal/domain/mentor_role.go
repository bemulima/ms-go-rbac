package domain

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

const (
	MentorRoleProofIssuer                  = "ms-go-auth"
	MentorRoleProofAudience                = "ms-go-rbac-mentor-role"
	MentorRoleProofType                    = "mentor_role_decision"
	MentorRoleProofPurpose                 = "AUTH_RBAC_MENTOR_ROLE_DECISION_V1"
	MentorRole                             = "mentor"
	MentorRoleService                      = "ms-go-mentor"
	MentorRoleDecisionApprove              = "APPROVE"
	MentorRoleDecisionSuspend              = "SUSPEND"
	MentorRoleProofMaxAgeSeconds           = 30
	MentorRoleProofFutureSkewSeconds       = 5
	MentorRoleProofMaxTimestamp      int64 = 1<<53 - 1
)

var (
	ErrMentorRoleInvalidCommand  = errors.New("invalid mentor role command")
	ErrMentorRoleConflict        = errors.New("mentor role command binding conflicts with existing state")
	ErrMentorRoleStaleRevision   = errors.New("mentor role command is behind the current revision fence")
	ErrMentorRoleInvalidSnapshot = errors.New("inconsistent mentor role snapshot")
)

// MentorRoleCommand is the immutable business binding, not authorization.
// Assertion JTI, lifetime, raw proof and private credentials are not its identity.
type MentorRoleCommand struct {
	Issuer              string
	AdminID             string
	TargetUserID        string
	ApplicationID       string
	ApplicationRevision uint64
	Decision            string
	RequestID           string
	DecisionDigest      string
	Role                string
	Service             string
}

// MentorRoleProof is a value returned only after signature/claim admission.
// A caller must still recheck the current canonical-default Admin before any
// receipt/fence/grant access and mutation. It is not a persisted delegation.
type MentorRoleProof struct {
	Command     MentorRoleCommand
	JWTID       string
	ProofDigest string
	IssuedAt    int64
	ExpiresAt   int64
}

type MentorRoleProofVerifier interface {
	VerifyMentorRoleProof(context.Context, string) (MentorRoleProof, error)
}

// MentorRoleFence is the last applied command for both immutable application
// and target/service bindings. Suspended is a terminal v1 tombstone.
type MentorRoleFence struct {
	Command   MentorRoleCommand
	Active    bool
	Suspended bool
}

// MentorRoleCommandReceipt is historical. Applied.Active must never be used
// instead of the current fence to establish access after suspension.
type MentorRoleCommandReceipt struct {
	Command MentorRoleCommand
	Applied MentorRoleFence
}

// MentorRoleSnapshot must be loaded atomically: receipt by issuer/request,
// application fence by application, and target fence by target/role/service.
// Nil is authoritative absence, never a failed or skipped lookup.
type MentorRoleSnapshot struct {
	Receipt          *MentorRoleCommandReceipt
	ApplicationFence *MentorRoleFence
	TargetFence      *MentorRoleFence
}

// MentorRolePlan is a pure decision, not a grant, durable receipt or repository.
// Write=true requires an atomic caller-owned receipt/fence/scoped-grant commit.
type MentorRolePlan struct {
	Receipt MentorRoleCommandReceipt
	Current MentorRoleFence
	Replay  bool
	Write   bool
}

func ValidMentorRoleCommand(command MentorRoleCommand) bool {
	if command.Issuer != MentorRoleProofIssuer || command.Role != MentorRole || command.Service != MentorRoleService ||
		!validMentorRoleUUID(command.AdminID) || !validMentorRoleUUID(command.TargetUserID) ||
		!validMentorRoleUUID(command.ApplicationID) || !validMentorRoleUUID(command.RequestID) {
		return false
	}
	switch command.Decision {
	case MentorRoleDecisionApprove:
		if command.ApplicationRevision != 2 {
			return false
		}
	case MentorRoleDecisionSuspend:
		if command.ApplicationRevision != 3 && command.ApplicationRevision != 4 {
			return false
		}
	default:
		return false
	}
	// This is Mentor's existing DecisionIntent digest. The target is separately
	// signed and pinned by the immutable application/target fence, not appended
	// to an incompatible digest format here.
	digest := sha256.Sum256([]byte(command.Decision + "|" + command.AdminID + "|" + command.ApplicationID + "|" + command.RequestID + "|" + strconv.FormatUint(command.ApplicationRevision-1, 10)))
	return command.DecisionDigest == hex.EncodeToString(digest[:])
}

// PlanMentorRoleCommand is deliberately not an authorization application or
// in-memory role store. It assumes its caller authenticated a fresh proof and
// rechecked the canonical Admin before loading this exact atomic snapshot.
// The future adapter must commit the plan under the same serialization fence;
// evaluating this function by itself never grants access or proves durability.
func PlanMentorRoleCommand(command MentorRoleCommand, snapshot MentorRoleSnapshot) (MentorRolePlan, error) {
	if !ValidMentorRoleCommand(command) {
		return MentorRolePlan{}, ErrMentorRoleInvalidCommand
	}
	if receipt := snapshot.Receipt; receipt != nil {
		if !ValidMentorRoleCommand(receipt.Command) || receipt.Applied != mentorRoleFenceFor(receipt.Command) ||
			receipt.Command.Issuer != command.Issuer || receipt.Command.RequestID != command.RequestID {
			return MentorRolePlan{}, ErrMentorRoleInvalidSnapshot
		}
		if receipt.Command != command {
			return MentorRolePlan{}, ErrMentorRoleConflict
		}
	}
	// Check both indexes independently, including when the other lookup reports
	// absence. A new application must not evade an existing target tombstone.
	for _, fence := range []*MentorRoleFence{snapshot.ApplicationFence, snapshot.TargetFence} {
		if fence == nil {
			continue
		}
		if !ValidMentorRoleCommand(fence.Command) || *fence != mentorRoleFenceFor(fence.Command) {
			return MentorRolePlan{}, ErrMentorRoleInvalidSnapshot
		}
		if !sameMentorRoleBinding(command, fence.Command) {
			return MentorRolePlan{}, ErrMentorRoleConflict
		}
	}
	if (snapshot.ApplicationFence == nil) != (snapshot.TargetFence == nil) ||
		(snapshot.ApplicationFence != nil && *snapshot.ApplicationFence != *snapshot.TargetFence) {
		return MentorRolePlan{}, ErrMentorRoleInvalidSnapshot
	}
	current := snapshot.ApplicationFence
	if receipt := snapshot.Receipt; receipt != nil {
		if current == nil || current.Command.ApplicationRevision < receipt.Command.ApplicationRevision {
			return MentorRolePlan{}, ErrMentorRoleInvalidSnapshot
		}
		if current.Command.ApplicationRevision == receipt.Command.ApplicationRevision {
			if current.Command != receipt.Command {
				return MentorRolePlan{}, ErrMentorRoleInvalidSnapshot
			}
		} else if receipt.Command.Decision != MentorRoleDecisionApprove || current.Command.Decision != MentorRoleDecisionSuspend {
			return MentorRolePlan{}, ErrMentorRoleInvalidSnapshot
		}
		// Return the immutable historical result alongside currentness. An old
		// APPROVE receipt cannot be interpreted as a current role or rewritten.
		return MentorRolePlan{Receipt: *receipt, Current: *current, Replay: true}, nil
	}
	if current != nil {
		if current.Command.RequestID == command.RequestID {
			if current.Command != command {
				return MentorRolePlan{}, ErrMentorRoleConflict
			}
			// A previously applied command without its receipt is storage drift,
			// not permission to repair or manufacture a historical receipt.
			return MentorRolePlan{}, ErrMentorRoleInvalidSnapshot
		}
		if command.ApplicationRevision < current.Command.ApplicationRevision {
			return MentorRolePlan{}, ErrMentorRoleStaleRevision
		}
		if command.ApplicationRevision == current.Command.ApplicationRevision || current.Suspended {
			return MentorRolePlan{}, ErrMentorRoleConflict
		}
	}
	fence := mentorRoleFenceFor(command)
	return MentorRolePlan{
		Receipt: MentorRoleCommandReceipt{Command: command, Applied: fence},
		Current: fence,
		Write:   true,
	}, nil
}

func mentorRoleFenceFor(command MentorRoleCommand) MentorRoleFence {
	return MentorRoleFence{Command: command, Active: command.Decision == MentorRoleDecisionApprove, Suspended: command.Decision == MentorRoleDecisionSuspend}
}

func sameMentorRoleBinding(left, right MentorRoleCommand) bool {
	return left.Issuer == right.Issuer && left.ApplicationID == right.ApplicationID &&
		left.TargetUserID == right.TargetUserID && left.Role == right.Role && left.Service == right.Service
}

func validMentorRoleUUID(value string) bool {
	return ValidPrincipalID(value) && value == strings.ToLower(value)
}
