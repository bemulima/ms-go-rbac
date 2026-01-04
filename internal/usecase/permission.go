package usecase

import (
	"context"

	"github.com/example/ms-rbac-service/internal/adapters/postgres"
	"github.com/example/ms-rbac-service/pkg/pagination"
)

type PermissionUsecase struct {
	repo *repo.PermissionRepository
}

func NewPermissionUsecase(r *repo.PermissionRepository) *PermissionUsecase {
	return &PermissionUsecase{repo: r}
}

func (uc *PermissionUsecase) Create(ctx context.Context, action, resourceKind string) (*repo.Permission, error) {
	item := &repo.Permission{Action: action, ResourceKind: resourceKind}
	if err := uc.repo.Create(ctx, item); err != nil {
		return nil, err
	}
	return item, nil
}

func (uc *PermissionUsecase) Update(ctx context.Context, id string, attrs map[string]interface{}) error {
	return uc.repo.Update(ctx, id, attrs)
}

func (uc *PermissionUsecase) Get(ctx context.Context, id string) (*repo.Permission, error) {
	return uc.repo.Get(ctx, id)
}

func (uc *PermissionUsecase) List(ctx context.Context, params pagination.Params) ([]repo.Permission, int64, error) {
	return uc.repo.List(ctx, params.Offset(), params.PageSize)
}
