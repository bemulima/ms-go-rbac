// Operator-only local CLI. It is never mounted in the HTTP or NATS server.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/example/ms-rbac-service/internal/domain/repository"
	repo "github.com/example/ms-rbac-service/internal/infrastructure/persistence/postgres"
	"github.com/example/ms-rbac-service/internal/usecase"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"os"
	"time"
)

type bootstrapService interface {
	Bootstrap(context.Context, repository.OperatorBootstrap) (repository.BootstrapReceipt, error)
}
type opener func(context.Context, string, string, string) (bootstrapService, func(), error)

func run(args []string, env func(string) string, output io.Writer, open opener) error {
	if env("APP_ENV") != "local-operator" || env("RBAC_OPERATOR_BOOTSTRAP") != "enabled" || env("RBAC_OPERATOR_ENVIRONMENT") != "learning-workspace-local" {
		return errors.New("operator environment denied")
	}
	f := flag.NewFlagSet("ms-rbac-operator-bootstrap", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var in repository.OperatorBootstrap
	var database, user string
	f.StringVar(&in.RequestID, "request-id", "", "exact UUID operation")
	f.StringVar(&in.PrincipalID, "principal-id", "", "exact registered principal UUID")
	f.StringVar(&in.Role, "role", "", "explicit moderator or admin")
	f.StringVar(&in.ExpectedRole, "expected-role", "", "must explicitly be student")
	f.StringVar(&in.Operator, "operator", "", "operator audit name")
	f.StringVar(&database, "database", "", "expected local database")
	f.StringVar(&user, "database-user", "", "expected database principal")
	if f.Parse(args) != nil || f.NArg() != 0 || database != "lw_rbac" || user == "" || env("DB_DSN") == "" {
		return errors.New("operator arguments denied")
	}
	in.Environment = env("RBAC_OPERATOR_ENVIRONMENT")
	if err := usecase.ValidateOperatorBootstrap(in); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	service, close, err := open(ctx, env("DB_DSN"), database, user)
	if err != nil {
		return errors.New("operator database authority unavailable")
	}
	defer close()
	receipt, err := service.Bootstrap(ctx, in)
	if err != nil {
		return errors.New("operator grant denied or unavailable")
	}
	return json.NewEncoder(output).Encode(receipt)
}
func openDatabase(ctx context.Context, dsn, database, user string) (bootstrapService, func(), error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, nil, err
	}
	if cfg.ConnConfig.Port != 5432 || (cfg.ConnConfig.Host != "platform-postgres" && cfg.ConnConfig.Host != "localhost" && cfg.ConnConfig.Host != "127.0.0.1") {
		return nil, nil, errors.New("nonlocal database denied")
	}
	for _, fallback := range cfg.ConnConfig.Fallbacks {
		if fallback.Port != 5432 || (fallback.Host != "platform-postgres" && fallback.Host != "localhost" && fallback.Host != "127.0.0.1") {
			return nil, nil, errors.New("nonlocal database fallback denied")
		}
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, nil, err
	}
	fail := func() (bootstrapService, func(), error) {
		pool.Close()
		return nil, nil, errors.New("database identity denied")
	}
	var db, actor string
	var super bool
	if err = pool.QueryRow(ctx, "SELECT current_database(),current_user,rolsuper FROM pg_roles WHERE rolname=current_user").Scan(&db, &actor, &super); err != nil {
		return fail()
	}
	if db != database || actor != user || super {
		return fail()
	}
	return usecase.NewPrincipalRoleUsecase(repo.NewPrincipalRoleRepository(pool)), pool.Close, nil
}
func main() {
	if err := run(os.Args[1:], os.Getenv, os.Stdout, openDatabase); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
