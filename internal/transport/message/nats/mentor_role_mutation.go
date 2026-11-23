package nats

import (
	"context"
	"time"
	"unicode/utf8"

	"github.com/example/ms-rbac-service/internal/domain"
	"github.com/example/ms-rbac-service/internal/usecase"
)

const (
	MentorRoleMutationSubject       = "rbac.applyMentorRole.v1"
	mentorRoleMutationEnvelopeLimit = 16384
	mentorRoleMutationProofLimit    = 8192
	mentorRoleMutationTimeout       = 5 * time.Second
)

// MentorRoleMutationConsumer is an unmounted, strict request/reply handler.
// Its concrete application verifies the Auth proof and uses the atomic owner
// store. No generic role assignment, subscription or HTTP write is introduced.
type MentorRoleMutationConsumer struct {
	Mutation *usecase.MentorRoleMutation
}

func (c *MentorRoleMutationConsumer) Handle(ctx context.Context, actualSubject string, body []byte) ([]byte, error) {
	if c == nil || c.Mutation == nil || ctx == nil || ctx.Err() != nil || actualSubject != MentorRoleMutationSubject {
		return nil, domain.ErrAuthorityUnavailable
	}
	operation, cancel := context.WithTimeout(ctx, mentorRoleMutationTimeout)
	defer cancel()
	var request permissionCheckRequest
	if len(body) == 0 || len(body) > mentorRoleMutationEnvelopeLimit || !utf8.Valid(body) ||
		decodePermissionCheckRequest(body, &request) != nil || len(request.Proof) > mentorRoleMutationProofLimit {
		return mentorRoleMutationReply(operation, `{"error":"invalid_proof"}`)
	}
	// Preserve the original compact proof. The real use case admits it before
	// any store access and pins the same bytes at each transaction recheck.
	_, err := c.Mutation.Apply(operation, request.Proof)
	if operation.Err() != nil {
		// The transaction may already have committed. Returning no ACK is an
		// unknown outcome, never an assertion that the mutation was rolled back.
		return nil, domain.ErrAuthorityUnavailable
	}
	switch err {
	case nil:
		// Do not expose a historical receipt, current fence or role state. This
		// unsigned ACK is not authority; Mentor must use signed scoped readback.
		return mentorRoleMutationReply(operation, `{"ok":true}`)
	case domain.ErrUnauthenticated, domain.ErrMentorRoleInvalidCommand:
		return mentorRoleMutationReply(operation, `{"error":"invalid_proof"}`)
	case domain.ErrMentorRoleForbidden:
		return mentorRoleMutationReply(operation, `{"error":"forbidden"}`)
	case domain.ErrMentorRoleConflict, domain.ErrMentorRoleStaleRevision:
		return mentorRoleMutationReply(operation, `{"error":"conflict"}`)
	default:
		return mentorRoleMutationReply(operation, `{"error":"unavailable"}`)
	}
}

func mentorRoleMutationReply(ctx context.Context, body string) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, domain.ErrAuthorityUnavailable
	}
	return []byte(body), nil
}
