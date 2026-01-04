package usecase

import (
	"context"

	"github.com/example/ms-rbac-service/internal/adapters/postgres"
)

// RolePermissionFilter defines filters for listing role permissions.
type RolePermissionFilter struct {
	RoleKey string
}

type RolePermissionUsecase struct {
	repo *repo.RolePermissionRepository
}

func NewRolePermissionUsecase(r *repo.RolePermissionRepository) *RolePermissionUsecase {
	return &RolePermissionUsecase{repo: r}
}

func (uc *RolePermissionUsecase) Create(ctx context.Context, input repo.RolePermissionCreate) error {
	return uc.repo.Create(ctx, input)
}

func (uc *RolePermissionUsecase) List(ctx context.Context, filter RolePermissionFilter) ([]repo.Permission, error) {
	return uc.repo.ListByRoleKey(ctx, filter.RoleKey)
}
