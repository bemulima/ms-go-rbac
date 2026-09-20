//go:build integration
// +build integration

package integration

import (
	"context"
	"net/http"
	"os"
	"testing"

	repo "github.com/example/ms-rbac-service/internal/infrastructure/persistence/postgres"
	httptransport "github.com/example/ms-rbac-service/internal/transport/http"
	adminhandlers "github.com/example/ms-rbac-service/internal/transport/http/admin/v1/handlers"
	apihandlers "github.com/example/ms-rbac-service/internal/transport/http/api/v1/handlers"
	"github.com/example/ms-rbac-service/internal/usecase"
	"github.com/jackc/pgx/v5/pgxpool"
)

// newHTTPHandler composes only the HTTP dependencies exercised by this contract suite.
func newHTTPHandler(t *testing.T) http.Handler {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), getenvRequired(t, "DB_DSN"))
	if err != nil {
		t.Fatalf("connect postgres: %v", err)
	}
	t.Cleanup(pool.Close)

	serviceRepo := repo.NewServiceRepository(pool)
	roleRepo := repo.NewRoleRepository(pool)
	permissionRepo := repo.NewPermissionRepository(pool)
	principalRoleRepo := repo.NewPrincipalRoleRepository(pool)
	rolePermissionRepo := repo.NewRolePermissionRepository(pool)

	serviceUC := usecase.NewServiceUsecase(serviceRepo)
	roleUC := usecase.NewRoleUsecase(roleRepo)
	permissionUC := usecase.NewPermissionUsecase(permissionRepo)
	rolePermissionUC := usecase.NewRolePermissionUsecase(rolePermissionRepo)
	principalRoleUC := usecase.NewPrincipalRoleUsecase(principalRoleRepo)
	principalPermissionUC := usecase.NewPrincipalPermissionUsecase(principalRoleRepo, rolePermissionRepo)

	router := httptransport.NewRouter(
		&adminhandlers.AdminHandlers{
			Service:        &adminhandlers.ServiceHandler{Usecase: serviceUC},
			Role:           &adminhandlers.RoleHandler{Usecase: roleUC},
			Permission:     &adminhandlers.PermissionHandler{Usecase: permissionUC},
			RolePermission: &adminhandlers.RolePermissionHandler{Usecase: rolePermissionUC},
		},
		&apihandlers.APIHandlers{
			PrincipalRole:       &apihandlers.PrincipalRoleHandler{Usecase: principalRoleUC},
			PrincipalPermission: &apihandlers.PrincipalPermissionHandler{Usecase: principalPermissionUC},
		},
	)
	return router.Handler()
}

func getenvRequired(t *testing.T, key string) string {
	t.Helper()
	value := os.Getenv(key)
	if value == "" {
		t.Fatalf("%s is required", key)
	}
	return value
}
