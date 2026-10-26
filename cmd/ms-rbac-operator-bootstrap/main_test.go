package main

import (
	"bytes"
	"context"
	"errors"
	"github.com/example/ms-rbac-service/internal/domain/repository"
	"github.com/example/ms-rbac-service/internal/usecase"
	"testing"
)

type memoryOperatorRepo struct {
	role    string
	receipt *repository.BootstrapReceipt
	writes  int
}

func (m *memoryOperatorRepo) Get(context.Context, string) (string, error) { return m.role, nil }
func (m *memoryOperatorRepo) Update(_ context.Context, _ string, v repository.PrincipalRoleUpdate) error {
	m.role = v.RoleKey
	return nil
}
func (m *memoryOperatorRepo) Bootstrap(ctx context.Context, v repository.OperatorBootstrap) (repository.BootstrapReceipt, error) {
	if m.receipt != nil {
		if m.receipt.OperatorBootstrap != v || m.role != v.Role {
			return repository.BootstrapReceipt{}, errors.New("conflict")
		}
		return *m.receipt, nil
	}
	if m.role != v.ExpectedRole {
		return repository.BootstrapReceipt{}, errors.New("conflict")
	}
	_ = m.Update(ctx, v.PrincipalID, repository.PrincipalRoleUpdate{RoleKey: v.Role})
	m.writes++
	m.receipt = &repository.BootstrapReceipt{OperatorBootstrap: v, AppliedAt: "fixed"}
	return *m.receipt, nil
}

var goodArgs = []string{"--request-id", "11111111-1111-4111-8111-111111111111", "--principal-id", "22222222-2222-4222-8222-222222222222", "--role", "moderator", "--expected-role", "student", "--operator", "local-owner", "--database", "lw_rbac", "--database-user", "lw_rbac"}

func TestOperatorGuardsBeforeConnection(t *testing.T) {
	good := map[string]string{"APP_ENV": "local-operator", "RBAC_OPERATOR_BOOTSTRAP": "enabled", "RBAC_OPERATOR_ENVIRONMENT": "learning-workspace-local", "DB_DSN": "private"}
	for _, missing := range []string{"APP_ENV", "RBAC_OPERATOR_BOOTSTRAP", "RBAC_OPERATOR_ENVIRONMENT", "DB_DSN"} {
		called := false
		open := func(context.Context, string, string, string) (bootstrapService, func(), error) {
			called = true
			return nil, nil, errors.New("unexpected")
		}
		env := func(k string) string {
			if k == missing {
				return ""
			}
			return good[k]
		}
		if run(goodArgs, env, &bytes.Buffer{}, open) == nil || called {
			t.Fatalf("guard %s", missing)
		}
	}
}
func TestOperatorAcceptedIdempotentAndConflict(t *testing.T) {
	repo := &memoryOperatorRepo{role: "student"}
	app := usecase.NewPrincipalRoleUsecase(repo)
	env := func(k string) string {
		return map[string]string{"APP_ENV": "local-operator", "RBAC_OPERATOR_BOOTSTRAP": "enabled", "RBAC_OPERATOR_ENVIRONMENT": "learning-workspace-local", "DB_DSN": "private"}[k]
	}
	open := func(context.Context, string, string, string) (bootstrapService, func(), error) {
		return app, func() {}, nil
	}
	var first, second bytes.Buffer
	if err := run(goodArgs, env, &first, open); err != nil {
		t.Fatal(err)
	}
	if err := run(goodArgs, env, &second, open); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() || repo.writes != 1 || repo.role != "moderator" {
		t.Fatal("not idempotent")
	}
	changed := append([]string{}, goodArgs...)
	changed[5] = "admin"
	if run(changed, env, &bytes.Buffer{}, open) == nil || repo.writes != 1 {
		t.Fatal("conflict accepted")
	}
	repo.role = "student"
	if run(goodArgs, env, &bytes.Buffer{}, open) == nil || repo.writes != 1 {
		t.Fatal("drift repaired")
	}
}

func TestOperatorInvalidIntentNeverConnects(t *testing.T) {
	env := func(k string) string {
		return map[string]string{"APP_ENV": "local-operator", "RBAC_OPERATOR_BOOTSTRAP": "enabled", "RBAC_OPERATOR_ENVIRONMENT": "learning-workspace-local", "DB_DSN": "private"}[k]
	}
	for _, index := range []int{1, 3, 5, 7, 9, 11, 13} {
		args := append([]string{}, goodArgs...)
		args[index] = ""
		called := false
		open := func(context.Context, string, string, string) (bootstrapService, func(), error) {
			called = true
			return nil, nil, errors.New("unexpected")
		}
		if run(args, env, &bytes.Buffer{}, open) == nil || called {
			t.Fatalf("missing argument %d connected", index)
		}
	}
}
func TestExplicitOperatorAdminIsNotAutomatic(t *testing.T) {
	repo := &memoryOperatorRepo{role: "student"}
	app := usecase.NewPrincipalRoleUsecase(repo)
	in := repository.OperatorBootstrap{RequestID: goodArgs[1], PrincipalID: goodArgs[3], Role: "admin", ExpectedRole: "student", Operator: "owner", Environment: "learning-workspace-local"}
	if _, err := app.Bootstrap(context.Background(), in); err != nil || repo.role != "admin" {
		t.Fatalf("explicit authorized operator grant: %v", err)
	}
}
