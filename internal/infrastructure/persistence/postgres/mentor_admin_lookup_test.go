package repo_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/example/ms-rbac-service/internal/domain"
	postgres "github.com/example/ms-rbac-service/internal/infrastructure/persistence/postgres"
	"github.com/example/ms-rbac-service/internal/usecase"
	"github.com/jackc/pgx/v5"
)

var _ domain.MentorCanonicalAdminRoleReader = (*postgres.PrincipalRoleRepository)(nil)

type mentorAdminQueryFixture struct {
	query string
	args  []any
	calls int
}

func (db *mentorAdminQueryFixture) Begin(context.Context) (pgx.Tx, error) {
	return nil, errors.New("read-only lookup must not begin a write transaction")
}

func (db *mentorAdminQueryFixture) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	db.calls++
	db.query, db.args = query, args
	return mentorAdminQueryRow{}
}

type mentorAdminQueryRow struct{}

func (mentorAdminQueryRow) Scan(dest ...any) error {
	*dest[0].(*string) = "admin"
	*dest[1].(*int64) = 1
	return nil
}

func TestMentorCanonicalAdminLookupUsesActualPostgresExactDefaultReader(t *testing.T) {
	const actor = "00000000-0000-4000-8000-000000000a01"
	db := &mentorAdminQueryFixture{}
	lookup := usecase.NewMentorCanonicalAdminLookup(postgres.NewPrincipalRoleRepository(db))
	allowed, err := lookup.Check(context.Background(), actor)
	if err != nil || !allowed || db.calls != 1 {
		t.Fatalf("actual exact-default repository path failed: %v", err)
	}
	for _, predicate := range []string{"pr.principal_id=$1", "pr.principal_kind=$2", "pr.tenant_id=$3", "pr.service_id=$4", "pr.resource_kind=$5", "pr.resource_id=$6", "COUNT(*)"} {
		if !strings.Contains(db.query, predicate) {
			t.Fatalf("exact canonical predicate missing: %s", predicate)
		}
	}
	want := []string{actor, "user", "00000000-0000-0000-0000-000000000000", "00000000-0000-0000-0000-000000000100", "global", "00000000-0000-0000-0000-000000000000"}
	if len(db.args) != len(want) {
		t.Fatal("wrong canonical tuple argument count")
	}
	for index, value := range want {
		if db.args[index] != value {
			t.Fatalf("wrong canonical tuple argument %d", index)
		}
	}
}
