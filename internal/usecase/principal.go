package usecase

import (
	"context"
	"strings"

	"github.com/example/ms-rbac-service/internal/domain"
	"github.com/example/ms-rbac-service/internal/domain/model"
	"github.com/example/ms-rbac-service/internal/domain/repository"
)

// PrincipalRoleUsecase handles principal role assignments.
type PrincipalRoleUsecase struct {
	repo repository.PrincipalRoleRepository
}

// NewPrincipalRoleUsecase constructs a new PrincipalRoleUsecase instance.
func NewPrincipalRoleUsecase(r repository.PrincipalRoleRepository) *PrincipalRoleUsecase {
	return &PrincipalRoleUsecase{repo: r}
}

// Update updates the principal's role assignment.
func (uc *PrincipalRoleUsecase) Update(ctx context.Context, principalID string, input repository.PrincipalRoleUpdate) error {
	input.RoleKey = strings.TrimSpace(input.RoleKey)
	current, err := uc.repo.Get(ctx, principalID)
	if err != nil {
		return err
	}
	if current == input.RoleKey && current != "" {
		return nil
	}
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
	roleRepo       repository.PrincipalPermissionRoleRepository
	permissionRepo repository.RolePermissionRepository
}

// NewPrincipalPermissionUsecase constructs a new PrincipalPermissionUsecase instance.
func NewPrincipalPermissionUsecase(roleRepo repository.PrincipalPermissionRoleRepository, permissionRepo repository.RolePermissionRepository) *PrincipalPermissionUsecase {
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

// HasKnowledgeGraphReview checks only the fixed reviewer entitlement at the
// canonical default scope. It fails closed when that scope is ambiguous.
func (uc *PrincipalPermissionUsecase) HasKnowledgeGraphReview(ctx context.Context, principalID string) (bool, error) {
	if !domain.ValidPrincipalID(principalID) {
		return false, domain.ErrUnauthenticated
	}
	role, err := uc.roleRepo.GetDefaultRole(ctx, principalID)
	if err != nil {
		return false, err
	}
	if role == "" {
		return false, nil
	}
	// Only the verified canonical default-scope admin is Super Admin.
	if role == "admin" {
		return true, nil
	}
	return uc.permissionRepo.HasDefaultPermission(ctx, role, domain.KnowledgeGraphReviewPermission, "")
}

func permissionIdentifier(perm model.Permission) string {
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
