package usecase

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"reflect"

	"github.com/example/ms-rbac-service/internal/domain"
)

// MentorRoleMutation admits a fresh Auth assertion on every invocation,
// including replay. Durable authority/currentness belongs to its atomic store.
type MentorRoleMutation struct {
	verifier domain.MentorRoleProofVerifier
	store    domain.MentorRoleMutationStore
}

func NewMentorRoleMutation(verifier domain.MentorRoleProofVerifier, store domain.MentorRoleMutationStore) *MentorRoleMutation {
	return &MentorRoleMutation{verifier: verifier, store: store}
}

func (mutation *MentorRoleMutation) Apply(ctx context.Context, rawProof string) (domain.MentorRolePlan, error) {
	if ctx == nil || ctx.Err() != nil || rawProof == "" {
		return domain.MentorRolePlan{}, domain.ErrUnauthenticated
	}
	if mutation == nil || missingMentorMutationDependency(mutation.verifier) {
		return domain.MentorRolePlan{}, domain.ErrAuthorityUnavailable
	}
	verifier := mutation.verifier
	admitted, err := verifier.VerifyMentorRoleProof(ctx, rawProof)
	if ctx.Err() != nil {
		return domain.MentorRolePlan{}, domain.ErrUnauthenticated
	}
	if err != nil {
		return domain.MentorRolePlan{}, mentorMutationAdmissionError(err)
	}
	digest := sha256.Sum256([]byte(rawProof))
	if !domain.ValidMentorRoleProofShape(admitted) || admitted.ProofDigest != hex.EncodeToString(digest[:]) {
		return domain.MentorRolePlan{}, domain.ErrUnauthenticated
	}
	if missingMentorMutationDependency(mutation.store) {
		return domain.MentorRolePlan{}, domain.ErrAuthorityUnavailable
	}
	// Each callback verifies the original string, not a reconstructed token or
	// a renewed assertion for the same command. The complete value is pinned,
	// including JTI, exact-byte digest and lifetime. The store independently
	// repeats this equality check at every required transaction boundary.
	revalidate := func(transactionContext context.Context) (domain.MentorRoleProof, error) {
		if ctx.Err() != nil || transactionContext == nil || transactionContext.Err() != nil {
			return domain.MentorRoleProof{}, domain.ErrUnauthenticated
		}
		current, err := verifier.VerifyMentorRoleProof(transactionContext, rawProof)
		if ctx.Err() != nil || transactionContext.Err() != nil {
			return domain.MentorRoleProof{}, domain.ErrUnauthenticated
		}
		if err != nil {
			return domain.MentorRoleProof{}, mentorMutationAdmissionError(err)
		}
		if current != admitted {
			return domain.MentorRoleProof{}, domain.ErrUnauthenticated
		}
		return current, nil
	}
	result, err := mutation.store.ApplyMentorRole(ctx, admitted, revalidate)
	if err != nil {
		return domain.MentorRolePlan{}, mentorMutationStoreError(err)
	}
	// The adapter reports commit success here. Do not reauthenticate or reject
	// a subsequently cancelled context as though the completed commit rolled
	// back. This check only rejects an internally inconsistent returned value;
	// it does not assert that the store's transaction was undone.
	if !validMentorMutationResult(admitted.Command, result) {
		return domain.MentorRolePlan{}, domain.ErrMentorRoleInvalidSnapshot
	}
	return result, nil
}

func validMentorMutationResult(command domain.MentorRoleCommand, result domain.MentorRolePlan) bool {
	if result.Write == result.Replay || result.Receipt.Command != command ||
		(result.Write && result.Current != result.Receipt.Applied) {
		return false
	}
	receipt, current := result.Receipt, result.Current
	checked, err := domain.PlanMentorRoleCommand(command, domain.MentorRoleSnapshot{
		Receipt: &receipt, ApplicationFence: &current, TargetFence: &current,
	})
	return err == nil && checked.Receipt == result.Receipt && checked.Current == result.Current
}

func mentorMutationAdmissionError(err error) error {
	// Only exact owner sentinels establish a known semantic denial. A wrapped
	// or joined denial may also contain an outage and must remain unavailable.
	if err == domain.ErrUnauthenticated || err == context.Canceled || err == context.DeadlineExceeded {
		return domain.ErrUnauthenticated
	}
	return domain.ErrAuthorityUnavailable
}

func mentorMutationStoreError(err error) error {
	for _, allowed := range []error{
		domain.ErrMentorRoleForbidden, domain.ErrMentorRoleInvalidCommand, domain.ErrMentorRoleConflict,
		domain.ErrMentorRoleStaleRevision, domain.ErrMentorRoleInvalidSnapshot,
	} {
		if err == allowed {
			return allowed
		}
	}
	return mentorMutationAdmissionError(err)
}

func missingMentorMutationDependency(dependency any) bool {
	if dependency == nil {
		return true
	}
	value := reflect.ValueOf(dependency)
	switch value.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return value.IsNil()
	default:
		return false
	}
}
