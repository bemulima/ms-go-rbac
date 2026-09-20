package usecase

import (
	"context"

	"github.com/example/ms-rbac-service/internal/domain/model"
	"github.com/example/ms-rbac-service/internal/domain/repository"
)

// RolePermissionFilter defines filters for listing role permissions.
type RolePermissionFilter struct {
	RoleKey string
}

type RolePermissionUsecase struct {
	repo repository.RolePermissionRepository
}

func NewRolePermissionUsecase(r repository.RolePermissionRepository) *RolePermissionUsecase {
	return &RolePermissionUsecase{repo: r}
}

func (uc *RolePermissionUsecase) Create(ctx context.Context, input repository.RolePermissionCreate) error {
	return uc.repo.Create(ctx, input)
}

func (uc *RolePermissionUsecase) List(ctx context.Context, filter RolePermissionFilter) ([]model.Permission, error) {
	return uc.repo.ListByRoleKey(ctx, filter.RoleKey)
}
