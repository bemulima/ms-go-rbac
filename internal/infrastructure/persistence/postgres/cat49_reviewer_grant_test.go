package repo

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/example/ms-rbac-service/internal/domain/repository"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// CAT-49 persistence protocol test. Runs against the production repository
// method with a transaction-bound pgx fake; no SQL connection or role is used.
// Actual PostgreSQL constraints/locks require the separate opt-in SQL test.
type cat49ReviewerDB struct {
	roles                      map[string][]string
	grant                      *repository.CAT49ReviewerGrantReceipt
	roleWrites, receiptWrites  int
	failReceipt, missingSchema bool
}

type cat49ReviewerTx struct {
	pgx.Tx
	db    *cat49ReviewerDB
	next  cat49ReviewerDB
	locks int
}

type cat49ReviewerRow struct {
	values []any
	err    error
}

func (r cat49ReviewerRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(r.values) != len(dest) {
		return errors.New("unexpected CAT49 row shape")
	}
	for i, v := range r.values {
		switch p := dest[i].(type) {
		case *string:
			s, ok := v.(string)
			if !ok {
				return errors.New("CAT49 scan string mismatch")
			}
			*p = s
		case *bool:
			b, ok := v.(bool)
			if !ok {
				return errors.New("CAT49 scan bool mismatch")
			}
			*p = b
		case *int64:
			n, ok := v.(int64)
			if !ok {
				return errors.New("CAT49 scan count mismatch")
			}
			*p = n
		default:
			return fmt.Errorf("unsupported CAT49 scan destination %T", dest[i])
		}
	}
	return nil
}

func (d *cat49ReviewerDB) Begin(context.Context) (pgx.Tx, error) {
	next := *d
	next.roles = make(map[string][]string, len(d.roles))
	for k, v := range d.roles {
		next.roles[k] = append([]string(nil), v...)
	}
	if d.grant != nil {
		receipt := *d.grant
		next.grant = &receipt
	}
	return &cat49ReviewerTx{db: d, next: next}, nil
}
func (*cat49ReviewerDB) QueryRow(context.Context, string, ...any) pgx.Row {
	return cat49ReviewerRow{err: errors.New("CAT49 query outside transaction")}
}
func (tx *cat49ReviewerTx) Commit(context.Context) error   { *tx.db = tx.next; return nil }
func (tx *cat49ReviewerTx) Rollback(context.Context) error { return nil }
func (tx *cat49ReviewerTx) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if strings.Contains(sql, "pg_advisory_xact_lock") {
		tx.locks++
		return pgconn.NewCommandTag("SELECT 1"), nil
	}
	if tx.locks != 2 {
		return pgconn.CommandTag{}, errors.New("CAT49 principal and global locks not acquired")
	}
	if strings.Contains(sql, "INSERT INTO principal_role") {
		if args[2] != "role:moderator" {
			return pgconn.CommandTag{}, errors.New("CAT49 non-moderator grant")
		}
		principal := args[0].(string)
		tx.next.roles[principal] = append(tx.next.roles[principal], "moderator")
		tx.next.roleWrites++
		return pgconn.NewCommandTag("INSERT 0 1"), nil
	}
	return pgconn.CommandTag{}, errors.New("unexpected CAT49 write")
}
func (tx *cat49ReviewerTx) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	if tx.locks != 2 {
		return cat49ReviewerRow{err: errors.New("CAT49 missing ownership lock")}
	}
	switch {
	case strings.Contains(sql, "FROM cat49_disposable_reviewer_grant WHERE request_id"):
		if tx.next.missingSchema {
			return cat49ReviewerRow{err: errors.New("CAT49 missing receipt table")}
		}
		r := tx.next.grant
		if r == nil || r.RequestID != args[0] {
			return cat49ReviewerRow{err: pgx.ErrNoRows}
		}
		return cat49ReviewerRow{values: []any{r.RunID, r.RequestID, r.PrincipalID, r.AuthReceiptDigest, r.Operator, r.AppliedAt}}
	case strings.Contains(sql, "SELECT coalesce(string_agg"):
		roles := append([]string(nil), tx.next.roles[args[0].(string)]...)
		sort.Strings(roles)
		return cat49ReviewerRow{values: []any{strings.Join(roles, ",")}}
	case strings.Contains(sql, "SELECT EXISTS(SELECT 1 FROM cat49_disposable_reviewer_grant"):
		r := tx.next.grant
		return cat49ReviewerRow{values: []any{r != nil && (r.RunID == args[0] || r.PrincipalID == args[1])}}
	case strings.Contains(sql, "SELECT count(*) FROM principal_role"):
		return cat49ReviewerRow{values: []any{int64(len(tx.next.roles[args[0].(string)]))}}
	case strings.Contains(sql, "SELECT id::text FROM role WHERE key='moderator'"):
		return cat49ReviewerRow{values: []any{"role:moderator"}}
	case strings.Contains(sql, "INSERT INTO cat49_disposable_reviewer_grant"):
		if tx.next.failReceipt {
			return cat49ReviewerRow{err: errors.New("injected CAT49 receipt failure")}
		}
		if tx.next.grant != nil {
			return cat49ReviewerRow{err: errors.New("CAT49 unique receipt violation")}
		}
		tx.next.grant = &repository.CAT49ReviewerGrantReceipt{
			RunID: args[0].(string), RequestID: args[1].(string), PrincipalID: args[2].(string),
			AuthReceiptDigest: args[3].(string), Operator: args[4].(string), AppliedAt: "2026-11-20T00:00:00.000000Z",
		}
		tx.next.receiptWrites++
		return cat49ReviewerRow{values: []any{tx.next.grant.AppliedAt}}
	}
	return cat49ReviewerRow{err: errors.New("unexpected CAT49 query")}
}

func cat49ReviewerIntent() repository.CAT49ReviewerGrantIntent {
	return repository.CAT49ReviewerGrantIntent{
		RunID: "cat49b1717", RequestID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		PrincipalID:       "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		AuthReceiptDigest: "sha256:" + strings.Repeat("a", 64), Operator: "reviewer-owner",
	}
}
func cat49ReviewerState(d *cat49ReviewerDB) string {
	return fmt.Sprintf("%v|%v|%d|%d", d.roles, d.grant, d.roleWrites, d.receiptWrites)
}

func TestCAT49ReviewerPersistenceReplayConflictAndDrift(t *testing.T) {
	ctx := context.Background()
	db := &cat49ReviewerDB{roles: map[string][]string{}}
	store := NewPrincipalRoleRepository(db)
	in := cat49ReviewerIntent()
	first, err := store.GrantCAT49Reviewer(ctx, in)
	if err != nil || first.Schema != "cat49-disposable-reviewer-grant.v1" || first.Role != "moderator" ||
		db.roleWrites != 1 || db.receiptWrites != 1 || !reflect.DeepEqual(db.roles[in.PrincipalID], []string{"moderator"}) {
		t.Fatalf("initial atomic grant incorrect: %v", err)
	}
	before := cat49ReviewerState(db)
	for i := 0; i < 3; i++ {
		replay, err := store.GrantCAT49Reviewer(ctx, in)
		if err != nil || replay != first || cat49ReviewerState(db) != before {
			t.Fatalf("exact replay changed committed state: %v", err)
		}
	}
	variants := map[string]func(*repository.CAT49ReviewerGrantIntent){
		"changed-auth-proof": func(p *repository.CAT49ReviewerGrantIntent) {
			p.AuthReceiptDigest = "sha256:" + strings.Repeat("b", 64)
		},
		"changed-operator":                 func(p *repository.CAT49ReviewerGrantIntent) { p.Operator = "different-owner" },
		"same-request-foreign-principal":   func(p *repository.CAT49ReviewerGrantIntent) { p.PrincipalID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc" },
		"different-request-same-principal": func(p *repository.CAT49ReviewerGrantIntent) { p.RequestID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd" },
		"different-run-same-principal": func(p *repository.CAT49ReviewerGrantIntent) {
			p.RunID = "cat49other01"
			p.RequestID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
		},
		"different-request-same-run": func(p *repository.CAT49ReviewerGrantIntent) {
			p.RequestID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
			p.PrincipalID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
		},
	}
	for name, change := range variants {
		t.Run(name, func(t *testing.T) {
			next := in
			change(&next)
			if _, err := store.GrantCAT49Reviewer(ctx, next); err == nil || cat49ReviewerState(db) != before {
				t.Fatalf("binding conflict accepted or state mutated: %v", err)
			}
		})
	}
	for _, roles := range [][]string{{"student"}, {"moderator", "student"}, nil} {
		db.roles[in.PrincipalID] = append([]string(nil), roles...)
		before = cat49ReviewerState(db)
		if _, err := store.GrantCAT49Reviewer(ctx, in); err == nil || cat49ReviewerState(db) != before {
			t.Fatalf("role drift repaired/ignored (%v): %v", roles, err)
		}
	}
}

func TestCAT49ReviewerPersistenceRejectsPreexistingRoles(t *testing.T) {
	in := cat49ReviewerIntent()
	for _, roles := range [][]string{{"student"}, {"admin"}, {"student", "moderator"}} {
		db := &cat49ReviewerDB{roles: map[string][]string{in.PrincipalID: append([]string(nil), roles...)}}
		before := cat49ReviewerState(db)
		if _, err := NewPrincipalRoleRepository(db).GrantCAT49Reviewer(context.Background(), in); err == nil || cat49ReviewerState(db) != before {
			t.Fatalf("foreign/existing principal adopted (%v): %v", roles, err)
		}
	}
}
func TestCAT49ReviewerPersistenceRollsBackFailedReceipt(t *testing.T) {
	in := cat49ReviewerIntent()
	db := &cat49ReviewerDB{roles: map[string][]string{}, failReceipt: true}
	before := cat49ReviewerState(db)
	if _, err := NewPrincipalRoleRepository(db).GrantCAT49Reviewer(context.Background(), in); err == nil || cat49ReviewerState(db) != before {
		t.Fatalf("role committed without immutable receipt: %v", err)
	}
	db.failReceipt = false
	if _, err := NewPrincipalRoleRepository(db).GrantCAT49Reviewer(context.Background(), in); err != nil || db.roleWrites != 1 || db.receiptWrites != 1 {
		t.Fatalf("exact recovery after failed transaction: %v", err)
	}
}
func TestCAT49ReviewerPersistenceFailsClosedWithoutSchema(t *testing.T) {
	db := &cat49ReviewerDB{roles: map[string][]string{}, missingSchema: true}
	before := cat49ReviewerState(db)
	if _, err := NewPrincipalRoleRepository(db).GrantCAT49Reviewer(context.Background(), cat49ReviewerIntent()); err == nil || cat49ReviewerState(db) != before {
		t.Fatalf("missing receipt schema authorized grant: %v", err)
	}
}
