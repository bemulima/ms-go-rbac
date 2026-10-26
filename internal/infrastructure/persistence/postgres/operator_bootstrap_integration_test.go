//go:build integration

package repo_test

import (
	"context"
	"github.com/example/ms-rbac-service/internal/domain"
	"github.com/example/ms-rbac-service/internal/domain/repository"
	repo "github.com/example/ms-rbac-service/internal/infrastructure/persistence/postgres"
	"github.com/example/ms-rbac-service/internal/usecase"
	"sync"
	"testing"
)

// Opt-in real PostgreSQL acceptance; no database/server/migration is created here.
// The existing signupSQLPool guard refuses canonical lw_rbac and requires an
// already migrated, owned loopback *_test database. Default source tests skip it.
func TestOperatorBootstrapSQLConcurrentReceiptAndDrift(t *testing.T) {
	pool := signupSQLPool(t)
	ctx := context.Background()
	var ready bool
	if err := pool.QueryRow(ctx, "SELECT to_regclass('public.operator_bootstrap_receipt') IS NOT NULL").Scan(&ready); err != nil || !ready {
		t.Fatal("owner must apply 004 to isolated test DB first")
	}
	in := repository.OperatorBootstrap{Role: "moderator", ExpectedRole: "student", Operator: "owner", Environment: "learning-workspace-local"}
	in.RequestID = signupSQLUUID(t)
	in.PrincipalID = signupSQLUUID(t)
	signupSQLFixture(t, pool, in.PrincipalID, "student", domain.SignupTenantID)
	app := usecase.NewPrincipalRoleUsecase(repo.NewPrincipalRoleRepository(pool))
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := app.Bootstrap(ctx, in); errs <- err }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent grant/replay: %v", err)
		}
	}
	first, err := app.Bootstrap(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	second, err := app.Bootstrap(ctx, in)
	if err != nil || first != second {
		t.Fatal("receipt replay differs")
	}
	var receipts, roles int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM operator_bootstrap_receipt WHERE principal_id=$1", in.PrincipalID).Scan(&receipts); err != nil || receipts != 1 {
		t.Fatal("receipt duplication")
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM principal_role WHERE principal_id=$1", in.PrincipalID).Scan(&roles); err != nil || roles != 1 {
		t.Fatal("grant duplication")
	}
	changed := in
	changed.Role = "admin"
	if _, err := app.Bootstrap(ctx, changed); err == nil {
		t.Fatal("changed role accepted")
	}
	// This explicit drift mutation is isolated SQL test data, never an operational repair.
	if err := repo.NewPrincipalRoleRepository(pool).Update(ctx, in.PrincipalID, repository.PrincipalRoleUpdate{RoleKey: "student"}); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Bootstrap(ctx, in); err == nil {
		t.Fatal("operator receipt repaired role drift")
	}
	if _, err := pool.Exec(ctx, "UPDATE operator_bootstrap_receipt SET operator_name='changed' WHERE request_id=$1", in.RequestID); err == nil {
		t.Fatal("immutable receipt changed")
	}
}
