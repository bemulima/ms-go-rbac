package repo

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/example/ms-rbac-service/internal/domain"
	"github.com/jackc/pgx/v5"
)

type principalRoleLookupDB struct {
	roleKey string
	count   int64
	err     error
	query   string
	args    []any
}

func (db *principalRoleLookupDB) Begin(context.Context) (pgx.Tx, error) {
	return nil, errors.New("unexpected transaction")
}

func (db *principalRoleLookupDB) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	db.query = query
	db.args = args
	return principalRoleLookupRow{roleKey: db.roleKey, count: db.count, err: db.err}
}

type principalRoleLookupRow struct {
	roleKey string
	count   int64
	err     error
}

func (row principalRoleLookupRow) Scan(dest ...any) error {
	if row.err != nil {
		return row.err
	}
	*dest[0].(*string) = row.roleKey
	*dest[1].(*int64) = row.count
	return nil
}

func TestPrincipalRoleRepositoryGetDefaultRoleUsesOnlyCanonicalTuple(t *testing.T) {
	const principalID = "00000000-0000-4000-8000-000000000901"
	db := &principalRoleLookupDB{roleKey: "reviewer", count: 1}
	role, err := NewPrincipalRoleRepository(db).GetDefaultRole(context.Background(), principalID)
	if err != nil || role != "reviewer" {
		t.Fatalf("GetDefaultRole() = (%q, %v), want (reviewer, nil)", role, err)
	}
	if !strings.Contains(db.query, "pr.tenant_id=$3") || !strings.Contains(db.query, "pr.service_id=$4") ||
		!strings.Contains(db.query, "pr.resource_kind=$5") || !strings.Contains(db.query, "pr.resource_id=$6") {
		t.Fatalf("default role query omitted an exact scope predicate: %s", db.query)
	}
	wantArgs := []any{principalID, "user", defaultTenantID, defaultServiceID, defaultScopeKind, defaultResourceID}
	if !reflect.DeepEqual(db.args, wantArgs) {
		t.Fatalf("default role query args = %#v, want %#v", db.args, wantArgs)
	}
}

func TestPrincipalRoleRepositoryGetDefaultRoleFailsClosedOnMissingOrAmbiguousRows(t *testing.T) {
	for _, tc := range []struct {
		name      string
		roleKey   string
		count     int64
		queryErr  error
		wantRole  string
		wantError error
	}{
		{name: "missing", count: 0, wantRole: ""},
		{name: "one", roleKey: "reviewer", count: 1, wantRole: "reviewer"},
		{name: "ambiguous", roleKey: "reviewer", count: 2, wantError: domain.ErrAmbiguousPrincipalRole},
		{name: "query failure", queryErr: errors.New("database unavailable"), wantError: errors.New("database unavailable")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := &principalRoleLookupDB{roleKey: tc.roleKey, count: tc.count, err: tc.queryErr}
			role, err := NewPrincipalRoleRepository(db).GetDefaultRole(context.Background(), "00000000-0000-4000-8000-000000000901")
			if role != tc.wantRole {
				t.Fatalf("role = %q, want %q", role, tc.wantRole)
			}
			if tc.wantError == nil && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.name == "ambiguous" && !errors.Is(err, tc.wantError) {
				t.Fatalf("ambiguous error = %v, want %v", err, tc.wantError)
			}
			if tc.queryErr != nil && !errors.Is(err, tc.queryErr) {
				t.Fatalf("query error = %v, want underlying error", err)
			}
		})
	}
}
