package usecase

import (
	"context"

	"github.com/example/ms-rbac-service/internal/adapters/postgres"
	"github.com/example/ms-rbac-service/pkg/pagination"
)

type ServiceUsecase struct {
	repo *repo.Repository
}

func NewServiceUsecase(r *repo.Repository) *ServiceUsecase {
	return &ServiceUsecase{repo: r}
}

func (uc *ServiceUsecase) Create(ctx context.Context, key, title string) (*repo.Service, error) {
	svc := &repo.Service{Key: key, Title: title}
	if err := uc.repo.CreateService(ctx, svc); err != nil {
		return nil, err
	}
	return svc, nil
}

func (uc *ServiceUsecase) Update(ctx context.Context, id, title string) error {
	return uc.repo.UpdateService(ctx, id, title)
}

func (uc *ServiceUsecase) Get(ctx context.Context, id string) (*repo.Service, error) {
	return uc.repo.GetService(ctx, id)
}

func (uc *ServiceUsecase) List(ctx context.Context, params pagination.Params) ([]repo.Service, int64, error) {
	return uc.repo.ListServices(ctx, params.Offset(), params.PageSize)
}
