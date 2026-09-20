package usecase

import (
	"context"

	"github.com/example/ms-rbac-service/internal/domain/model"
	"github.com/example/ms-rbac-service/internal/domain/repository"
	"github.com/example/ms-rbac-service/pkg/pagination"
)

type PermissionUsecase struct {
	repo repository.PermissionRepository
}

func NewPermissionUsecase(r repository.PermissionRepository) *PermissionUsecase {
	return &PermissionUsecase{repo: r}
}

func (uc *PermissionUsecase) Create(ctx context.Context, action, resourceKind string) (*model.Permission, error) {
	item := &model.Permission{Action: action, ResourceKind: resourceKind}
	if err := uc.repo.Create(ctx, item); err != nil {
		return nil, err
	}
	return item, nil
}

func (uc *PermissionUsecase) Update(ctx context.Context, id string, attrs map[string]interface{}) error {
	return uc.repo.Update(ctx, id, attrs)
}

func (uc *PermissionUsecase) Get(ctx context.Context, id string) (*model.Permission, error) {
	return uc.repo.Get(ctx, id)
}

func (uc *PermissionUsecase) List(ctx context.Context, params pagination.Params) ([]model.Permission, int64, error) {
	return uc.repo.List(ctx, params.Offset(), params.PageSize)
}
