package app

import (
	"context"
	"net/http"
	"time"

	"github.com/example/ms-rbac-service/internal/config"
	"github.com/example/ms-rbac-service/internal/repo"
	"github.com/example/ms-rbac-service/internal/server"
	"github.com/example/ms-rbac-service/internal/usecase"
)

// Bootstrap wires dependencies and returns an HTTP server instance.
func Bootstrap() (*http.Server, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}

	repository := repo.New()
	serviceUC := usecase.NewServiceUsecase(repository)
	roleUC := usecase.NewRoleUsecase(repository)
	permissionUC := usecase.NewPermissionUsecase(repository)

	srv := server.New(serviceUC, roleUC, permissionUC)
	httpServer := &http.Server{
		Addr:    cfg.HTTPAddr,
		Handler: srv,
	}
	return httpServer, nil
}

// Shutdown gracefully terminates the HTTP server.
func Shutdown(ctx context.Context, srv *http.Server) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return srv.Shutdown(ctx)
}
