package repo

import (
	"errors"

	"github.com/example/ms-rbac-service/internal/domain"
)

var (
	ErrNotFound       = domain.ErrNotFound
	ErrNotImplemented = errors.New("not implemented")
)
