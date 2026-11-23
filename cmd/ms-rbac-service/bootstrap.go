package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/example/ms-rbac-service/internal/config"
	"github.com/example/ms-rbac-service/internal/infrastructure/client"
	natsclient "github.com/example/ms-rbac-service/internal/infrastructure/messaging/nats"
	repo "github.com/example/ms-rbac-service/internal/infrastructure/persistence/postgres"
	httptransport "github.com/example/ms-rbac-service/internal/transport/http"
	adminhandlers "github.com/example/ms-rbac-service/internal/transport/http/admin/v1/handlers"
	apihandlers "github.com/example/ms-rbac-service/internal/transport/http/api/v1/handlers"
	privatehandlers "github.com/example/ms-rbac-service/internal/transport/http/private"
	natstransport "github.com/example/ms-rbac-service/internal/transport/message/nats"
	"github.com/example/ms-rbac-service/internal/usecase"
	"github.com/jackc/pgx/v5/pgxpool"
	natsgo "github.com/nats-io/nats.go"
)

var dbPool *pgxpool.Pool
var legacyNATSConnection *natsgo.Conn
var mentorOwnerRuntime *MentorOwnerRuntime

// bootstrap is the service composition root.
func bootstrap() (*http.Server, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	// Explicit opt-in is preflighted before any database or broker connection.
	// Disabled mode does not consult Mentor keys, files or transport settings.
	mentorPrepared, err := prepareMentorOwner(cfg)
	if err != nil {
		return nil, err
	}

	signupVerifier, err := client.NewSignupProofVerifier(cfg.AuthSignupPublicKey)
	if err != nil {
		return nil, err
	}
	reviewerProofVerifier, err := client.NewAuthReviewerPermissionProofVerifier(cfg.AuthJWTPublicKey, cfg.AuthJWTIssuer)
	if err != nil {
		return nil, err
	}
	reviewerDecisionSigner, err := client.NewReviewerPermissionDecisionSigner(cfg.ReviewerPermissionDecisionPrivateKey)
	if err != nil {
		log.Printf("reviewer permission decisions disabled: %v", err)
		reviewerDecisionSigner = nil
	}

	if cfg.DBDSN == "" {
		return nil, fmt.Errorf("DB_DSN is required")
	}

	pool, err := connectPostgresWithRetry(cfg.DBDSN)
	if err != nil {
		return nil, err
	}
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
	signupUC := usecase.NewSignupProvisioner(signupVerifier, repo.NewSignupProvisioningRepository(pool))
	principalPermissionUC := usecase.NewPrincipalPermissionUsecase(principalRoleRepo, rolePermissionRepo)
	if cfg.MCPStudentRBACEnabled && cfg.NATSURL == "" {
		pool.Close()
		return nil, fmt.Errorf("MCP Student RBAC requires NATS")
	}

	adminHandlers := &adminhandlers.AdminHandlers{
		Service:        &adminhandlers.ServiceHandler{Usecase: serviceUC},
		Role:           &adminhandlers.RoleHandler{Usecase: roleUC},
		Permission:     &adminhandlers.PermissionHandler{Usecase: permissionUC},
		RolePermission: &adminhandlers.RolePermissionHandler{Usecase: rolePermissionUC},
	}
	apiHandlers := &apihandlers.APIHandlers{
		PrincipalRole:       &apihandlers.PrincipalRoleHandler{Usecase: principalRoleUC},
		PrincipalPermission: &apihandlers.PrincipalPermissionHandler{Usecase: principalPermissionUC},
	}
	router := httptransport.NewRouter(adminHandlers, apiHandlers)
	if cfg.IDEStudentRoleEnabled {
		router.SetIDEStudentRoleRead(&privatehandlers.IDEStudentRoleHandler{
			Enabled: true, Token: cfg.IDEStudentRoleToken,
			Roles: principalRoleRepo,
		})
	}

	var legacyConn *natsgo.Conn
	if cfg.NATSURL != "" {
		conn, err := connectNATSWithRetry(cfg.NATSURL)
		if err != nil {
			pool.Close()
			return nil, err
		}
		legacyConn = conn

		assigner := natstransport.RoleAssigner{
			Conn:     conn,
			Subject:  "rbac.assign-role",
			Queue:    "ms-go-rbac",
			SignupUC: signupUC,
		}
		if err := assigner.Listen(); err != nil {
			log.Printf("nats subscribe failed (rbac.assign-role): %v", err)
		}

		checker := natstransport.RoleChecker{
			Conn:        conn,
			Subject:     "rbac.checkRole",
			Queue:       "ms-go-rbac",
			PrincipalUC: principalRoleUC,
		}
		if err := checker.Listen(); err != nil {
			log.Printf("nats subscribe failed (rbac.checkRole): %v", err)
		}

		// CAT-49 Practice Catalog requires an exact global/default-scope Student read.
		// This is internal NATS read-only; broker subject ACLs remain a deployment gate.
		defaultStudentChecker := natstransport.DefaultStudentRoleChecker{
			Conn: conn, Roles: principalRoleRepo,
		}
		if err := defaultStudentChecker.Listen(); err != nil {
			log.Printf("nats subscribe failed (rbac.checkDefaultStudentRole): %v", err)
		}

		permissionChecker := natstransport.PermissionChecker{
			Conn: conn, Subject: "rbac.checkPermission", Queue: "ms-go-rbac",
			ProofVerifier: reviewerProofVerifier, DecisionSigner: reviewerDecisionSigner, Permission: principalPermissionUC,
		}
		if err := permissionChecker.Listen(); err != nil {
			log.Printf("nats subscribe failed (rbac.checkPermission): %v", err)
		}
		if cfg.MCPStudentRBACEnabled {
			if err := registerMCPStudentHandlers(conn, cfg, principalPermissionUC); err != nil {
				conn.Close()
				pool.Close()
				return nil, fmt.Errorf("MCP Student RBAC bootstrap failed: %w", err)
			}
		}
	}
	mentorRuntime, err := startMentorOwner(context.Background(), mentorPrepared, pool, dialMentorOwner)
	if err != nil {
		if legacyConn != nil {
			legacyConn.Close()
		}
		pool.Close()
		return nil, err
	}
	dbPool, legacyNATSConnection, mentorOwnerRuntime = pool, legacyConn, mentorRuntime
	httpServer := &http.Server{
		Addr:    cfg.HTTPAddr,
		Handler: router.Handler(),
	}
	return httpServer, nil
}

// shutdown always cleans owned resources, including after listener failure.
// Mentor is drained before its pool is closed; a deadline forces transport close.
func shutdown(ctx context.Context, srv *http.Server) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var failures []error
	if srv != nil {
		if err := srv.Shutdown(ctx); err != nil {
			_ = srv.Close()
			failures = append(failures, err)
		}
	}
	if err := mentorOwnerRuntime.Close(ctx); err != nil {
		failures = append(failures, err)
	}
	if legacyNATSConnection != nil {
		legacyNATSConnection.Close()
	}
	if dbPool != nil {
		dbPool.Close()
	}
	return errors.Join(failures...)
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
		conn, err := natsclient.Connect(url)
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
