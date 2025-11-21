package usecase

import (
	"context"
	"strings"

	"github.com/example/ms-rbac-service/internal/repo"
)

// PrincipalUsecase handles user-focused RBAC operations such as role assignment
// and lookup that are required by ms-go-user.
type PrincipalUsecase struct {
	repo *repo.Repository
}

// NewPrincipalUsecase constructs a new PrincipalUsecase instance.
func NewPrincipalUsecase(r *repo.Repository) *PrincipalUsecase {
	return &PrincipalUsecase{repo: r}
}

// AssignRole associates a role key with a principal identifier.
func (uc *PrincipalUsecase) AssignRole(ctx context.Context, principalID, role string) error {
	return uc.repo.AssignPrincipalRole(ctx, principalID, role)
}

// GetRole returns the role key associated with the principal.
func (uc *PrincipalUsecase) GetRole(ctx context.Context, principalID string) (string, error) {
	return uc.repo.GetPrincipalRole(ctx, principalID)
}

// GetPermissions returns the formatted permission strings assigned to the principal's current role.
func (uc *PrincipalUsecase) GetPermissions(ctx context.Context, principalID string) ([]string, error) {
	role, err := uc.GetRole(ctx, principalID)
	if err != nil {
		return nil, err
	}
	role = strings.TrimSpace(role)
	if role == "" {
		return []string{}, nil
	}
	perms, err := uc.repo.ListPermissionsForRole(ctx, role)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(perms))
	result := make([]string, 0, len(perms))
	for _, perm := range perms {
		if identifier := permissionIdentifier(perm); identifier != "" {
			if _, ok := seen[identifier]; ok {
				continue
			}
			seen[identifier] = struct{}{}
			result = append(result, identifier)
		}
	}
	return result, nil
}

// CheckRole returns true if the principal has the requested role key.
func (uc *PrincipalUsecase) CheckRole(ctx context.Context, principalID, role string) (bool, error) {
	current, err := uc.GetRole(ctx, principalID)
	if err != nil {
		return false, err
	}
	return current == role && current != "", nil
}

// CheckPermission always returns false for now because permission tracking is a TODO.
func (uc *PrincipalUsecase) CheckPermission(ctx context.Context, principalID, permission string) (bool, error) {
	perms, err := uc.GetPermissions(ctx, principalID)
	if err != nil {
		return false, err
	}
	for _, p := range perms {
		if p == permission {
			return true, nil
		}
	}
	return false, nil
}

func permissionIdentifier(perm repo.Permission) string {
	switch {
	case perm.Action == "" && perm.ResourceKind == "":
		return ""
	case perm.Action != "" && perm.ResourceKind != "":
		return perm.Action + ":" + perm.ResourceKind
	case perm.Action != "":
		return perm.Action
	default:
		return perm.ResourceKind
	}
}
