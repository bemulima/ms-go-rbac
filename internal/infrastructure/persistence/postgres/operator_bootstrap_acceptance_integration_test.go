//go:build integration

package repo_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/example/ms-rbac-service/internal/domain"
	"github.com/example/ms-rbac-service/internal/domain/repository"
	repo "github.com/example/ms-rbac-service/internal/infrastructure/persistence/postgres"
	"github.com/example/ms-rbac-service/internal/usecase"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestOperatorBootstrapSQLAtomicityAndDenials(t *testing.T) {
	pool := signupSQLPool(t) // Existing fail-closed loopback *_test guard.
	ctx := context.Background()
	app := usecase.NewPrincipalRoleUsecase(repo.NewPrincipalRoleRepository(pool))
	intent := func(role string) repository.OperatorBootstrap {
		principal := signupSQLUUID(t)
		signupSQLFixture(t, pool, principal, "student", domain.SignupTenantID)
		return repository.OperatorBootstrap{RequestID: signupSQLUUID(t), PrincipalID: principal, Role: role, ExpectedRole: "student", Operator: "sql-acceptance", Environment: "learning-workspace-local"}
	}
	assertState := func(in repository.OperatorBootstrap, role string, receipts int) {
		t.Helper()
		got, err := repo.NewPrincipalRoleRepository(pool).Get(ctx, in.PrincipalID)
		var count int
		if err != nil || got != role || pool.QueryRow(ctx, "SELECT count(*) FROM operator_bootstrap_receipt WHERE principal_id=$1", in.PrincipalID).Scan(&count) != nil || count != receipts {
			t.Fatalf("state mismatch: role=%q receipts=%d err=%v", got, count, err)
		}
	}

	t.Run("receipt_failure_rolls_back_grant", func(t *testing.T) {
		in := intent("admin")
		// Test-only fault after the real assignment helper, before receipt commit.
		constraint := "operator_acceptance_reject_receipt"
		_, err := pool.Exec(ctx, fmt.Sprintf("ALTER TABLE operator_bootstrap_receipt ADD CONSTRAINT %s CHECK (request_id <> '%s'::uuid)", constraint, in.RequestID))
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := pool.Exec(ctx, "ALTER TABLE operator_bootstrap_receipt DROP CONSTRAINT "+constraint); err != nil {
				t.Error(err)
			}
		}()
		if _, err := app.Bootstrap(ctx, in); err == nil {
			t.Fatal("injected receipt failure accepted")
		}
		assertState(in, "student", 0)
	})

	t.Run("competing_grants_only_one_commits", func(t *testing.T) {
		first := intent("admin")
		second := first
		second.RequestID, second.Role = signupSQLUUID(t), "moderator"
		var wg sync.WaitGroup
		type result struct {
			in  repository.OperatorBootstrap
			err error
		}
		results := make(chan result, 2)
		for _, in := range []repository.OperatorBootstrap{first, second} {
			wg.Add(1)
			go func(in repository.OperatorBootstrap) {
				defer wg.Done()
				_, err := app.Bootstrap(ctx, in)
				results <- result{in, err}
			}(in)
		}
		wg.Wait()
		close(results)
		var winner repository.OperatorBootstrap
		wins := 0
		for r := range results {
			if r.err == nil {
				winner, wins = r.in, wins+1
			}
		}
		if wins != 1 {
			t.Fatalf("committed grants=%d", wins)
		}
		assertState(winner, winner.Role, 1)
		before, err := app.Bootstrap(ctx, winner)
		if err != nil {
			t.Fatal(err)
		}
		after, err := app.Bootstrap(ctx, winner)
		if err != nil || before != after {
			t.Fatal("exact replay changed receipt", err)
		}
		for _, statement := range []string{"UPDATE operator_bootstrap_receipt SET operator_name='altered' WHERE request_id=$1", "DELETE FROM operator_bootstrap_receipt WHERE request_id=$1"} {
			if _, err := pool.Exec(ctx, statement, winner.RequestID); err == nil {
				t.Fatal("immutable receipt mutation accepted")
			}
		}
		assertState(winner, winner.Role, 1)
	})

	t.Run("unexpected_current_role_denied", func(t *testing.T) {
		in := intent("admin")
		if err := repo.NewPrincipalRoleRepository(pool).Update(ctx, in.PrincipalID, repository.PrincipalRoleUpdate{RoleKey: "moderator"}); err != nil {
			t.Fatal(err)
		}
		if _, err := app.Bootstrap(ctx, in); err == nil {
			t.Fatal("overwrote unexpected existing role")
		}
		assertState(in, "moderator", 0)
	})

	t.Run("read_only_authority_denied_without_partial_grant", func(t *testing.T) {
		in := intent("admin")
		cfg, err := pgxpool.ParseConfig(os.Getenv("RBAC_SIGNUP_TEST_DATABASE_URL"))
		if err != nil {
			t.Fatal("isolated config unavailable")
		}
		cfg.ConnConfig.RuntimeParams["default_transaction_read_only"] = "on"
		readonly, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatal("readonly isolated pool unavailable")
		}
		defer readonly.Close()
		if _, err := usecase.NewPrincipalRoleUsecase(repo.NewPrincipalRoleRepository(readonly)).Bootstrap(ctx, in); err == nil {
			t.Fatal("readonly transaction granted role")
		}
		assertState(in, "student", 0)
	})

	t.Run("populated_migration_down_refuses", func(t *testing.T) {
		raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "migrations", "004_operator_bootstrap_receipts.down.sql"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, string(raw)); err == nil {
			t.Fatal("populated receipt table was removed")
		}
		var exists bool
		if pool.QueryRow(ctx, "SELECT to_regclass('public.operator_bootstrap_receipt') IS NOT NULL").Scan(&exists) != nil || !exists {
			t.Fatal("migration down lost receipts")
		}
	})
}
