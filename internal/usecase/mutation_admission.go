package usecase

import (
	"context"

	"github.com/example/ms-rbac-service/internal/domain"
)

// MutationAdmission establishes identity before any HTTP mutation processing.
// No administrative grant matrix is accepted yet, so verified actors are denied.
type MutationAdmission struct {
	verifier domain.AccessIdentityVerifier
}

func NewMutationAdmission(verifier domain.AccessIdentityVerifier) *MutationAdmission {
	return &MutationAdmission{verifier: verifier}
}

func (a *MutationAdmission) Admit(ctx context.Context, token string) error {
	if token == "" {
		return domain.ErrUnauthenticated
	}
	if a == nil || a.verifier == nil {
		return domain.ErrAuthorityUnavailable
	}
	actor, err := a.verifier.VerifyAccessToken(ctx, token)
	if err != nil {
		return err
	}
	if !domain.ValidPrincipalID(actor.PrincipalID) {
		return domain.ErrAuthorityUnavailable
	}
	return domain.ErrMutationForbidden
}
