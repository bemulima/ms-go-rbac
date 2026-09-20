package usecase

import (
	"context"

	"github.com/example/ms-rbac-service/internal/domain/model"
	"github.com/example/ms-rbac-service/internal/domain/repository"
	"github.com/example/ms-rbac-service/pkg/pagination"
)

type ServiceUsecase struct {
	repo repository.ServiceRepository
}

func NewServiceUsecase(r repository.ServiceRepository) *ServiceUsecase {
	return &ServiceUsecase{repo: r}
}

func (uc *ServiceUsecase) Create(ctx context.Context, key, title string) (*model.Service, error) {
	svc := &model.Service{Key: key, Title: title}
	if err := uc.repo.Create(ctx, svc); err != nil {
		return nil, err
	}
	return svc, nil
}

func (uc *ServiceUsecase) Update(ctx context.Context, id, title string) error {
	return uc.repo.Update(ctx, id, title)
}

func (uc *ServiceUsecase) Get(ctx context.Context, id string) (*model.Service, error) {
	return uc.repo.Get(ctx, id)
}

func (uc *ServiceUsecase) List(ctx context.Context, params pagination.Params) ([]model.Service, int64, error) {
	return uc.repo.List(ctx, params.Offset(), params.PageSize)
}
