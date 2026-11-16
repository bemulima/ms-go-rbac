package usecase

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/example/ms-rbac-service/internal/domain"
)

func TestMentorRoleMutationRPCErrorClassificationRejectsAmbiguousDependencies(t *testing.T) {
	proof := mentorMutationProof(mentorMutationCommand(domain.MentorRoleDecisionApprove, 2))
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"joined unauthenticated", errors.Join(domain.ErrUnauthenticated, domain.ErrAuthorityUnavailable)},
		{"wrapped unauthenticated", fmt.Errorf("private diagnostics: %w", domain.ErrUnauthenticated)},
		{"joined forbidden", errors.Join(domain.ErrMentorRoleForbidden, domain.ErrAuthorityUnavailable)},
		{"wrapped forbidden", fmt.Errorf("private diagnostics: %w", domain.ErrMentorRoleForbidden)},
		{"joined conflict", errors.Join(domain.ErrMentorRoleConflict, domain.ErrAuthorityUnavailable)},
		{"wrapped conflict", fmt.Errorf("private diagnostics: %w", domain.ErrMentorRoleConflict)},
		{"joined stale", errors.Join(domain.ErrMentorRoleStaleRevision, domain.ErrAuthorityUnavailable)},
		{"wrapped invalid command", fmt.Errorf("private diagnostics: %w", domain.ErrMentorRoleInvalidCommand)},
		{"joined cancellation", errors.Join(context.Canceled, errors.New("private outage"))},
		{"wrapped deadline", fmt.Errorf("private diagnostics: %w", context.DeadlineExceeded)},
	} {
		t.Run(tc.name+" at verifier", func(t *testing.T) {
			verifier := &mentorMutationVerifier{verify: func(context.Context, string) (domain.MentorRoleProof, error) {
				return proof, tc.err
			}}
			store := &mentorMutationStore{apply: func(context.Context, domain.MentorRoleProof, domain.MentorRoleProofRevalidator) (domain.MentorRolePlan, error) {
				t.Fatal("ambiguous failed admission reached store")
				return domain.MentorRolePlan{}, nil
			}}
			result, err := NewMentorRoleMutation(verifier, store).Apply(context.Background(), mentorMutationRawProof)
			if result != (domain.MentorRolePlan{}) || err != domain.ErrAuthorityUnavailable || store.calls != 0 {
				t.Fatal("ambiguous verifier failure became a semantic denial")
			}
		})
		t.Run(tc.name+" at store", func(t *testing.T) {
			store := &mentorMutationStore{apply: func(context.Context, domain.MentorRoleProof, domain.MentorRoleProofRevalidator) (domain.MentorRolePlan, error) {
				return domain.MentorRolePlan{}, tc.err
			}}
			result, err := NewMentorRoleMutation(mentorMutationStableVerifier(proof), store).Apply(context.Background(), mentorMutationRawProof)
			if result != (domain.MentorRolePlan{}) || err != domain.ErrAuthorityUnavailable || store.calls != 1 {
				t.Fatal("ambiguous store failure became a semantic denial")
			}
		})
	}
}
