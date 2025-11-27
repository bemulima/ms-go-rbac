package usecase

import (
	"context"

	"github.com/example/ms-rbac-service/internal/adapter/postgres"
	"github.com/example/ms-rbac-service/pkg/pagination"
)

type PermissionUsecase struct {
	repo *repo.Repository
}

func NewPermissionUsecase(r *repo.Repository) *PermissionUsecase {
	return &PermissionUsecase{repo: r}
}

func (uc *PermissionUsecase) Create(ctx context.Context, action, resourceKind string) (*repo.Permission, error) {
	item := &repo.Permission{Action: action, ResourceKind: resourceKind}
	if err := uc.repo.CreatePermission(ctx, item); err != nil {
		return nil, err
	}
	return item, nil
}

func (uc *PermissionUsecase) Update(ctx context.Context, id string, attrs map[string]interface{}) error {
	return uc.repo.UpdatePermission(ctx, id, attrs)
}

func (uc *PermissionUsecase) Get(ctx context.Context, id string) (*repo.Permission, error) {
	return uc.repo.GetPermission(ctx, id)
}

func (uc *PermissionUsecase) List(ctx context.Context, params pagination.Params) ([]repo.Permission, int64, error) {
	return uc.repo.ListPermissions(ctx, params.Offset(), params.PageSize)
}

func (uc *PermissionUsecase) AssignToRole(ctx context.Context, roleKey, permissionID string) error {
	return uc.repo.AssignPermissionToRole(ctx, roleKey, permissionID)
}
