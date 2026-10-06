package usecase

import (
	"context"

	"github.com/example/ms-rbac-service/internal/domain"
)

type SignupProvisioner struct {
	verifier domain.SignupProofVerifier
	repo     domain.SignupProvisioningRepository
}

func NewSignupProvisioner(verifier domain.SignupProofVerifier, repo domain.SignupProvisioningRepository) *SignupProvisioner {
	return &SignupProvisioner{verifier: verifier, repo: repo}
}

func (s *SignupProvisioner) Provision(ctx context.Context, subject string, envelope []byte) error {
	if s == nil || s.verifier == nil {
		return domain.ErrAuthorityUnavailable
	}
	grant, err := s.verifier.VerifySignupProof(ctx, subject, envelope)
	if err != nil {
		return err
	}
	if !domain.ValidSignupIdentity(grant, subject) {
		return domain.ErrUnauthenticated
	}
	if !domain.ValidSignupBinding(grant, subject) {
		return domain.ErrSignupConflict
	}
	if s.repo == nil {
		return domain.ErrAuthorityUnavailable
	}
	return s.repo.ProvisionSignup(ctx, grant)
}
