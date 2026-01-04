package usecase

import (
	"context"

	"github.com/example/ms-rbac-service/internal/adapters/postgres"
	"github.com/example/ms-rbac-service/pkg/pagination"
)

type RoleUsecase struct {
	repo *repo.RoleRepository
}

func NewRoleUsecase(r *repo.RoleRepository) *RoleUsecase {
	return &RoleUsecase{repo: r}
}

func (uc *RoleUsecase) Create(ctx context.Context, key, title string) (*repo.Role, error) {
	role := &repo.Role{Key: key, Title: title}
	if err := uc.repo.Create(ctx, role); err != nil {
		return nil, err
	}
	return role, nil
}

func (uc *RoleUsecase) Update(ctx context.Context, id, title string) error {
	return uc.repo.Update(ctx, id, title)
}

func (uc *RoleUsecase) Get(ctx context.Context, id string) (*repo.Role, error) {
	return uc.repo.Get(ctx, id)
}

func (uc *RoleUsecase) List(ctx context.Context, params pagination.Params) ([]repo.Role, int64, error) {
	return uc.repo.List(ctx, params.Offset(), params.PageSize)
}
