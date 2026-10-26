package repo

import (
	"context"
	"errors"
	"github.com/example/ms-rbac-service/internal/domain/repository"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"reflect"
	"strings"
	"testing"
)

// Transaction protocol harness: executes the production repository method without
// a server, simulates rollback/unique conflicts, never touches a persistent DB.
type operatorDB struct {
	role          string
	receipt       *repository.BootstrapReceipt
	writes        int
	missingSchema bool
}
type operatorTx struct {
	pgx.Tx
	db     *operatorDB
	next   operatorDB
	locked bool
}
type operatorRow struct {
	values []string
	err    error
}

func (r operatorRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	for i, v := range r.values {
		reflect.ValueOf(dest[i]).Elem().SetString(v)
	}
	return nil
}
func (d *operatorDB) Begin(context.Context) (pgx.Tx, error) { return &operatorTx{db: d, next: *d}, nil }
func (d *operatorDB) QueryRow(context.Context, string, ...any) pgx.Row {
	return operatorRow{err: errors.New("query outside transaction")}
}
func (t *operatorTx) Commit(context.Context) error   { *t.db = t.next; return nil }
func (t *operatorTx) Rollback(context.Context) error { return nil }
func (t *operatorTx) Exec(_ context.Context, q string, args ...any) (pgconn.CommandTag, error) {
	if strings.Contains(q, "pg_advisory_xact_lock") {
		t.locked = true
		return pgconn.NewCommandTag("SELECT 1"), nil
	}
	if !t.locked {
		return pgconn.CommandTag{}, errors.New("lock missing")
	}
	switch {
	case strings.Contains(q, "DELETE FROM principal_role"):
		t.next.role = ""
	case strings.Contains(q, "INSERT INTO principal_role"):
		t.next.role = strings.TrimPrefix(args[2].(string), "role:")
		t.next.writes++
	default:
		return pgconn.CommandTag{}, errors.New("unexpected mutation")
	}
	return pgconn.NewCommandTag("UPDATE 1"), nil
}
func (t *operatorTx) QueryRow(_ context.Context, q string, args ...any) pgx.Row {
	if !t.locked {
		return operatorRow{err: errors.New("lock missing")}
	}
	switch {
	case strings.Contains(q, "FROM operator_bootstrap_receipt"):
		if t.next.missingSchema {
			return operatorRow{err: errors.New("missing receipt schema")}
		}
		r := t.next.receipt
		if r == nil || r.RequestID != args[0] {
			return operatorRow{err: pgx.ErrNoRows}
		}
		return operatorRow{values: []string{r.RequestID, r.PrincipalID, r.Role, r.ExpectedRole, r.Operator, r.Environment, r.AppliedAt}}
	case strings.Contains(q, "FROM principal_role"):
		if t.next.role == "" {
			return operatorRow{err: pgx.ErrNoRows}
		}
		return operatorRow{values: []string{t.next.role}}
	case strings.Contains(q, "SELECT id::text FROM role"):
		return operatorRow{values: []string{"role:" + args[0].(string)}}
	case strings.Contains(q, "INSERT INTO operator_bootstrap_receipt"):
		if t.next.receipt != nil {
			return operatorRow{err: errors.New("unique principal conflict")}
		}
		t.next.receipt = &repository.BootstrapReceipt{OperatorBootstrap: repository.OperatorBootstrap{RequestID: args[0].(string), PrincipalID: args[1].(string), Role: args[2].(string), ExpectedRole: args[3].(string), Operator: args[4].(string), Environment: args[5].(string)}, AppliedAt: "fixed"}
		return operatorRow{values: []string{"fixed"}}
	}
	return operatorRow{err: errors.New("unexpected query")}
}
func operatorIntent() repository.OperatorBootstrap {
	return repository.OperatorBootstrap{RequestID: "11111111-1111-4111-8111-111111111111", PrincipalID: "22222222-2222-4222-8222-222222222222", Role: "moderator", ExpectedRole: "student", Operator: "owner", Environment: "learning-workspace-local"}
}
func TestOperatorRepositoryAtomicReplayConflictAndDrift(t *testing.T) {
	ctx := context.Background()
	db := &operatorDB{role: "student"}
	r := NewPrincipalRoleRepository(db)
	in := operatorIntent()
	first, err := r.Bootstrap(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	second, err := r.Bootstrap(ctx, in)
	if err != nil || first != second || db.writes != 1 {
		t.Fatalf("replay: %v", err)
	}
	changed := in
	changed.Role = "admin"
	if _, err = r.Bootstrap(ctx, changed); err == nil || db.role != "moderator" || db.writes != 1 {
		t.Fatal("changed intent accepted")
	}
	db.role = "student"
	if _, err = r.Bootstrap(ctx, in); err == nil || db.role != "student" || db.writes != 1 {
		t.Fatal("drift repaired")
	}
	// A new request for the same principal rolls back grant if receipt uniqueness fails.
	changed = in
	changed.RequestID = "33333333-3333-4333-8333-333333333333"
	if _, err = r.Bootstrap(ctx, changed); err == nil || db.role != "student" || db.writes != 1 {
		t.Fatal("partial grant committed")
	}
}
func TestOperatorRepositoryFailsClosed(t *testing.T) {
	for _, db := range []*operatorDB{{role: "admin"}, {role: "student,admin"}, {role: "student,student"}, {role: ""}, {role: "student", missingSchema: true}} {
		before := db.role
		r := NewPrincipalRoleRepository(db)
		if _, err := r.Bootstrap(context.Background(), operatorIntent()); err == nil || db.role != before || db.writes != 0 {
			t.Fatal("unsafe bootstrap")
		}
	}
}
