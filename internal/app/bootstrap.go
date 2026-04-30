package app

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	httpadapter "github.com/example/ms-rbac-service/internal/adapters/http"
	"github.com/example/ms-rbac-service/internal/adapters/http/handlers"
	natsadapter "github.com/example/ms-rbac-service/internal/adapters/nats"
	"github.com/example/ms-rbac-service/internal/adapters/postgres"
	"github.com/example/ms-rbac-service/internal/config"
	"github.com/example/ms-rbac-service/internal/usecase"
	"github.com/jackc/pgx/v5/pgxpool"
	natsgo "github.com/nats-io/nats.go"
)

var dbPool *pgxpool.Pool

// Bootstrap wires dependencies and returns an HTTP server instance.
func Bootstrap() (*http.Server, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}

	if cfg.DBDSN == "" {
		return nil, fmt.Errorf("DB_DSN is required")
	}

	pool, err := connectPostgresWithRetry(cfg.DBDSN)
	if err != nil {
		return nil, err
	}
	dbPool = pool
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

	adminHandlers := &handlers.AdminHandlers{
		Service:        &handlers.ServiceHandler{Usecase: serviceUC},
		Role:           &handlers.RoleHandler{Usecase: roleUC},
		Permission:     &handlers.PermissionHandler{Usecase: permissionUC},
		RolePermission: &handlers.RolePermissionHandler{Usecase: rolePermissionUC},
	}
	apiHandlers := &handlers.APIHandlers{
		PrincipalRole:       &handlers.PrincipalRoleHandler{Usecase: principalRoleUC},
		PrincipalPermission: &handlers.PrincipalPermissionHandler{Usecase: principalPermissionUC},
	}
	router := httpadapter.NewRouter(adminHandlers, apiHandlers)

	if cfg.NATSURL != "" {
		conn, err := connectNATSWithRetry(cfg.NATSURL)
		if err != nil {
			pool.Close()
			return nil, err
		}

		assigner := natsadapter.RoleAssigner{
			Conn:        conn,
			Subject:     "rbac.assign-role",
			Queue:       "ms-go-rbac",
			PrincipalUC: principalRoleUC,
		}
		if err := assigner.Listen(); err != nil {
			log.Printf("nats subscribe failed (rbac.assign-role): %v", err)
		}

		checker := natsadapter.RoleChecker{
			Conn:        conn,
			Subject:     "rbac.checkRole",
			Queue:       "ms-go-rbac",
			PrincipalUC: principalRoleUC,
		}
		if err := checker.Listen(); err != nil {
			log.Printf("nats subscribe failed (rbac.checkRole): %v", err)
		}
	}
	httpServer := &http.Server{
		Addr:    cfg.HTTPAddr,
		Handler: router.Handler(),
	}
	return httpServer, nil
}

// Shutdown gracefully terminates the HTTP server.
func Shutdown(ctx context.Context, srv *http.Server) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		return err
	}
	if dbPool != nil {
		dbPool.Close()
	}
	return nil
}

func connectPostgresWithRetry(dsn string) (*pgxpool.Pool, error) {
	const (
		maxAttempts = 30
		retryDelay  = 2 * time.Second
	)

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		pool, err := pgxpool.New(ctx, dsn)
		if err == nil {
			err = pool.Ping(ctx)
		}
		cancel()

		if err == nil {
			return pool, nil
		}
		if pool != nil {
			pool.Close()
		}

		lastErr = err
		log.Printf("postgres connect attempt %d/%d failed: %v", attempt, maxAttempts, err)

		if attempt < maxAttempts {
			time.Sleep(retryDelay)
		}
	}

	return nil, fmt.Errorf("postgres connect failed after retries: %w", lastErr)
}

func connectNATSWithRetry(url string) (*natsgo.Conn, error) {
	const (
		maxAttempts = 30
		retryDelay  = 2 * time.Second
	)

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		conn, err := natsadapter.Connect(url)
		if err == nil {
			return conn, nil
		}

		lastErr = err
		log.Printf("nats connect attempt %d/%d failed: %v", attempt, maxAttempts, err)

		if attempt < maxAttempts {
			time.Sleep(retryDelay)
		}
	}

	return nil, fmt.Errorf("nats connect failed after retries: %w", lastErr)
}
