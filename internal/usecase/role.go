package usecase

import (
	"context"

	"github.com/example/ms-rbac-service/internal/domain/model"
	"github.com/example/ms-rbac-service/internal/domain/repository"
	"github.com/example/ms-rbac-service/pkg/pagination"
)

type RoleUsecase struct {
	repo repository.RoleRepository
}

func NewRoleUsecase(r repository.RoleRepository) *RoleUsecase {
	return &RoleUsecase{repo: r}
}

func (uc *RoleUsecase) Create(ctx context.Context, key, title string) (*model.Role, error) {
	role := &model.Role{Key: key, Title: title}
	if err := uc.repo.Create(ctx, role); err != nil {
		return nil, err
	}
	return role, nil
}

func (uc *RoleUsecase) Update(ctx context.Context, id, title string) error {
	return uc.repo.Update(ctx, id, title)
}

func (uc *RoleUsecase) Get(ctx context.Context, id string) (*model.Role, error) {
	return uc.repo.Get(ctx, id)
}

func (uc *RoleUsecase) List(ctx context.Context, params pagination.Params) ([]model.Role, int64, error) {
	return uc.repo.List(ctx, params.Offset(), params.PageSize)
}
