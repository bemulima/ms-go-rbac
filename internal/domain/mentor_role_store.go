package domain

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
)

// ErrMentorRoleForbidden means an authenticated actor is not the current
// unique canonical-default Admin at the store's serialized authority boundary.
var ErrMentorRoleForbidden = errors.New("current canonical Admin required for mentor role mutation")

// MentorRoleProofRevalidator is scoped to one synchronous invocation. It must
// verify the exact original Auth assertion again and return the same whole
// admitted value, or an error. It is not a stored delegation or a cached allow.
// The store must also compare each successful value to its admitted proof.
type MentorRoleProofRevalidator func(context.Context) (MentorRoleProof, error)

// MentorRoleMutationStore owns one atomic canonical-Admin check, receipt/fence
// transition and exact scoped assignment change, including no-write replay.
// It must revalidate before Begin, after blocking locks, and before commit;
// any failure before commit rolls back. It must not retain or log the callback
// or its raw proof. Neither a fabricated proof value nor a nil callback grants
// authority. Returned plans are internal historical receipts plus the current
// serialized fence, not signed fresh readback for Mentor private access.
type MentorRoleMutationStore interface {
	ApplyMentorRole(context.Context, MentorRoleProof, MentorRoleProofRevalidator) (MentorRolePlan, error)
}

// ValidMentorRoleProofShape checks only the value contract. It does not verify
// a signature, compare a raw proof digest, establish freshness or confer
// authority; an actual verifier and per-invocation revalidation remain required.
func ValidMentorRoleProofShape(proof MentorRoleProof) bool {
	if !ValidMentorRoleCommand(proof.Command) || !validMentorRoleUUID(proof.JWTID) ||
		len(proof.ProofDigest) != 64 || proof.ProofDigest != strings.ToLower(proof.ProofDigest) ||
		proof.IssuedAt <= 0 || proof.IssuedAt > MentorRoleProofMaxTimestamp ||
		proof.ExpiresAt <= 0 || proof.ExpiresAt > MentorRoleProofMaxTimestamp ||
		proof.ExpiresAt <= proof.IssuedAt {
		return false
	}
	if _, err := hex.DecodeString(proof.ProofDigest); err != nil {
		return false
	}
	// Both operands are positive and bounded before subtraction. The verifier,
	// not this shape-only helper, must compare them against its current clock.
	return proof.ExpiresAt-proof.IssuedAt <= MentorRoleProofMaxAgeSeconds
}
