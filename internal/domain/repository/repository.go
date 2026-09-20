// Package repository defines the persistence ports required by RBAC use cases.
package repository

import (
	"context"

	"github.com/example/ms-rbac-service/internal/domain/model"
)

type ServiceRepository interface {
	Create(context.Context, *model.Service) error
	Update(context.Context, string, string) error
	Get(context.Context, string) (*model.Service, error)
	List(context.Context, int, int) ([]model.Service, int64, error)
}

type RoleRepository interface {
	Create(context.Context, *model.Role) error
	Update(context.Context, string, string) error
	Get(context.Context, string) (*model.Role, error)
	List(context.Context, int, int) ([]model.Role, int64, error)
}

type PermissionRepository interface {
	Create(context.Context, *model.Permission) error
	Update(context.Context, string, map[string]interface{}) error
	Get(context.Context, string) (*model.Permission, error)
	List(context.Context, int, int) ([]model.Permission, int64, error)
}

type RolePermissionCreate struct {
	RoleKey      string
	PermissionID string
}

type RolePermissionRepository interface {
	Create(context.Context, RolePermissionCreate) error
	ListByRoleKey(context.Context, string) ([]model.Permission, error)
}

type PrincipalRoleUpdate struct {
	RoleKey string
}

type PrincipalRoleRepository interface {
	Update(context.Context, string, PrincipalRoleUpdate) error
	Get(context.Context, string) (string, error)
}
