package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/example/ms-rbac-service/internal/domain"
	"github.com/example/ms-rbac-service/internal/infrastructure/c2bfixture"
	repo "github.com/example/ms-rbac-service/internal/infrastructure/persistence/postgres"
	"github.com/example/ms-rbac-service/internal/usecase"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"os"
	"time"
)

func main() {
	if e := run(os.Args[1:], os.Stdin, os.Stdout); e != nil {
		fmt.Fprintln(os.Stderr, "C2-B RBAC bootstrap failed:", e.Error())
		os.Exit(1)
	}
}
func run(args []string, in io.Reader, out io.Writer) error {
	return runWithPool(args, in, out, pgxpool.NewWithConfig)
}
func runWithPool(args []string, in io.Reader, out io.Writer, open func(context.Context, *pgxpool.Config) (*pgxpool.Pool, error)) error {
	if len(args) != 1 || args[0] != "apply" {
		return errors.New("command denied")
	}
	dsn := os.Getenv("C2B_FIXTURE_DSN")
	m, config, e := c2bfixture.PrepareConnection("rbac", dsn)
	if e != nil {
		return e
	}
	raw, e := io.ReadAll(io.LimitReader(in, 16385))
	var signed domain.C2BSignedIntent
	if e != nil || c2bfixture.Strict(raw, &signed) != nil {
		return errors.New("bounded signed intent required")
	}
	i, e := c2bfixture.Verify(m, signed)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, e := open(ctx, config)
	if e != nil {
		return errors.New("isolated database unavailable")
	}
	defer pool.Close()
	receipt, e := usecase.ApplyC2BBootstrap(ctx, repo.C2BBootstrapRepository{Pool: pool}, i)
	if e != nil {
		return errors.New("role assignment transaction denied")
	}
	return json.NewEncoder(out).Encode(receipt)
}
