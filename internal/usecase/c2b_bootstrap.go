package usecase

import (
	"context"
	"errors"
	"github.com/example/ms-rbac-service/internal/domain"
)

type C2BRoleStore interface {
	ApplyC2B(context.Context, domain.C2BIntent) (domain.C2BReceipt, error)
}

func ApplyC2BBootstrap(ctx context.Context, s C2BRoleStore, i domain.C2BIntent) (domain.C2BReceipt, error) {
	if s == nil || !i.Valid() {
		return domain.C2BReceipt{}, errors.New("bootstrap denied")
	}
	return s.ApplyC2B(ctx, i)
}
