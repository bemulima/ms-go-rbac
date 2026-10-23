package usecase

import (
	"context"
	"errors"
	"github.com/example/ms-rbac-service/internal/domain/repository"
	"regexp"
)

var ErrBootstrapDenied = errors.New("operator bootstrap denied")
var canonicalOperatorUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var operatorName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

// Bootstrap is an operator capability composed ONLY by the standalone CLI.
// Existing assignments must match an explicit expected role; HTTP never calls it.
func (uc *PrincipalRoleUsecase) Bootstrap(ctx context.Context, input repository.OperatorBootstrap) (repository.BootstrapReceipt, error) {
	if err := ValidateOperatorBootstrap(input); err != nil {
		return repository.BootstrapReceipt{}, err
	}
	repo, ok := uc.repo.(repository.OperatorBootstrapRepository)
	if !ok {
		return repository.BootstrapReceipt{}, ErrBootstrapDenied
	}
	return repo.Bootstrap(ctx, input)
}

func ValidateOperatorBootstrap(input repository.OperatorBootstrap) error {

	if !canonicalOperatorUUID.MatchString(input.RequestID) || !canonicalOperatorUUID.MatchString(input.PrincipalID) || !operatorName.MatchString(input.Operator) || input.Environment != "learning-workspace-local" || (input.Role != "moderator" && input.Role != "admin") || input.ExpectedRole != "student" {
		return ErrBootstrapDenied
	}
	return nil
}
