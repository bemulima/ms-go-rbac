package usecase

import (
	"context"
	"strings"

	"github.com/example/ms-rbac-service/internal/adapters/postgres"
)

// PrincipalRoleUsecase handles principal role assignments.
type PrincipalRoleUsecase struct {
	repo *repo.PrincipalRoleRepository
}

// NewPrincipalRoleUsecase constructs a new PrincipalRoleUsecase instance.
func NewPrincipalRoleUsecase(r *repo.PrincipalRoleRepository) *PrincipalRoleUsecase {
	return &PrincipalRoleUsecase{repo: r}
}

// Update updates the principal's role assignment.
func (uc *PrincipalRoleUsecase) Update(ctx context.Context, principalID string, input repo.PrincipalRoleUpdate) error {
	input.RoleKey = strings.TrimSpace(input.RoleKey)
	return uc.repo.Update(ctx, principalID, input)
}

// Get returns the role key associated with the principal.
func (uc *PrincipalRoleUsecase) Get(ctx context.Context, principalID string) (string, error) {
	return uc.repo.Get(ctx, principalID)
}

// GetByRole checks whether the principal has the provided role.
func (uc *PrincipalRoleUsecase) GetByRole(ctx context.Context, principalID, role string) (bool, error) {
	current, err := uc.Get(ctx, principalID)
	if err != nil {
		return false, err
	}
	role = strings.TrimSpace(role)
	return current == role && current != "", nil
}

// PrincipalPermissionUsecase resolves permissions for principals.
type PrincipalPermissionUsecase struct {
	roleRepo       *repo.PrincipalRoleRepository
	permissionRepo *repo.RolePermissionRepository
}

// NewPrincipalPermissionUsecase constructs a new PrincipalPermissionUsecase instance.
func NewPrincipalPermissionUsecase(roleRepo *repo.PrincipalRoleRepository, permissionRepo *repo.RolePermissionRepository) *PrincipalPermissionUsecase {
	return &PrincipalPermissionUsecase{roleRepo: roleRepo, permissionRepo: permissionRepo}
}

// List returns the permission identifiers for the principal's current role.
func (uc *PrincipalPermissionUsecase) List(ctx context.Context, principalID string) ([]string, error) {
	role, err := uc.roleRepo.Get(ctx, principalID)
	if err != nil {
		return nil, err
	}
	role = strings.TrimSpace(role)
	if role == "" {
		return []string{}, nil
	}
	perms, err := uc.permissionRepo.ListByRoleKey(ctx, role)
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

// GetByPermission checks whether the principal has the requested permission.
func (uc *PrincipalPermissionUsecase) GetByPermission(ctx context.Context, principalID, permission string) (bool, error) {
	perms, err := uc.List(ctx, principalID)
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
