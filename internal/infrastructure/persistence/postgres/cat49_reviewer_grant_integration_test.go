//go:build integration

package repo_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/example/ms-rbac-service/internal/domain/repository"
	repo "github.com/example/ms-rbac-service/internal/infrastructure/persistence/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CAT-49 PostgreSQL persistence acceptance: never run by the default test suite.
// The owner must first approve and create a NEW, one-run, test-only disposable
// RBAC database with migration 005. This is NOT Reviewer operator execution.
type cat49SQLOwner struct {
	Schema, Purpose  string
	RunID            string `json:"run_id"`
	Project, Network string
	RBACDatabase     string `json:"rbac_database"`
	RBACUser         string `json:"rbac_user"`
	PostgresHost     string `json:"postgres_host"`
	PostgresServerIP string `json:"postgres_server_ip"`
	PostgresPort     uint16 `json:"postgres_port"`
}

func cat49SQLPool(t *testing.T) (*pgxpool.Pool, cat49SQLOwner) {
	t.Helper()
	if os.Getenv("RBAC_CAT49_SQL_APPROVAL") != "approved-disposable-test-only" {
		t.Skip("CAT49 PostgreSQL test needs separate disposable-only approval")
	}
	markerPath, dsn := os.Getenv("RBAC_CAT49_SQL_OWNER_MARKER_FILE"), os.Getenv("RBAC_CAT49_SQL_DATABASE_URL")
	if markerPath == "" || dsn == "" {
		t.Fatal("CAT49 approved SQL test needs exact owner marker and database URL")
	}
	stat, err := os.Lstat(markerPath)
	if err != nil || !stat.Mode().IsRegular() || stat.Mode().Perm()&0077 != 0 || stat.Size() < 1 || stat.Size() > 4096 {
		t.Fatal("CAT49 SQL owner marker must be private regular file")
	}
	bytes, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal("CAT49 SQL owner marker unreadable")
	}
	var m cat49SQLOwner
	if json.Unmarshal(bytes, &m) != nil {
		t.Fatal("CAT49 SQL owner marker invalid")
	}
	validRun := regexp.MustCompile(`^cat49[a-z0-9]{5,20}$`)
	validDB := regexp.MustCompile(`^cat49_[a-z0-9_]{4,60}_test$`)
	validUser := regexp.MustCompile(`^[a-z][a-z0-9_]{1,60}$`)
	if m.Schema != "cat49-disposable-ownership.v1" || m.Purpose != "cat49-reviewer" ||
		!validRun.MatchString(m.RunID) || m.Project != "lp-v1-"+m.RunID || m.Network != m.Project+"-net" ||
		!validDB.MatchString(m.RBACDatabase) || !validUser.MatchString(m.RBACUser) ||
		(m.PostgresHost != "127.0.0.1" && m.PostgresHost != "localhost") || m.PostgresPort == 0 {
		t.Fatal("CAT49 SQL database lacks exact test ownership")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil || cfg.ConnConfig.Database != m.RBACDatabase || cfg.ConnConfig.User != m.RBACUser ||
		cfg.ConnConfig.Host != m.PostgresHost || cfg.ConnConfig.Port != m.PostgresPort || len(cfg.ConnConfig.Fallbacks) != 0 {
		t.Fatal("CAT49 SQL connection identity or fallbacks denied")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal("CAT49 isolated SQL pool creation failed")
	}
	t.Cleanup(pool.Close)
	var db, user, server string
	var super, hasTable, hasTrigger bool
	err = pool.QueryRow(ctx, `SELECT current_database(),current_user,host(inet_server_addr()),
       (SELECT rolsuper FROM pg_roles WHERE rolname=current_user),
       to_regclass('public.cat49_disposable_reviewer_grant') IS NOT NULL,
       EXISTS(SELECT 1 FROM pg_trigger WHERE tgname='cat49_reviewer_grant_immutable' AND NOT tgisinternal)`).
		Scan(&db, &user, &server, &super, &hasTable, &hasTrigger)
	ip := net.ParseIP(server)
	expectedServerIP := net.ParseIP(m.PostgresServerIP)
	serverAllowed := ip != nil && (ip.IsLoopback() || (expectedServerIP != nil && ip.Equal(expectedServerIP)))
	if err != nil || db != m.RBACDatabase || user != m.RBACUser || super || !hasTable || !hasTrigger || !serverAllowed {
		t.Fatal("CAT49 real SQL server/user/migration identity refused")
	}
	var existing int64
	if pool.QueryRow(ctx, `SELECT count(*) FROM cat49_disposable_reviewer_grant WHERE run_id=$1`, m.RunID).Scan(&existing) != nil || existing != 0 {
		t.Fatal("CAT49 SQL acceptance requires a fresh disposable run; existing receipt must not be reused")
	}
	return pool, m
}

// This test runs only after explicit approval; it creates a synthetic RBAC
// assignment/receipt, never an Auth principal, sign-in session or JWT.
func TestCAT49ReviewerSQLAtomicReplayConflictAndDrift(t *testing.T) {
	pool, owner := cat49SQLPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	store := repo.NewPrincipalRoleRepository(pool)
	in := repository.CAT49ReviewerGrantIntent{
		RunID: owner.RunID, RequestID: signupSQLUUID(t), PrincipalID: signupSQLUUID(t),
		AuthReceiptDigest: "sha256:" + strings.Repeat("a", 64), Operator: "cat49-sql-test",
	}
	counts := func() (int64, int64) {
		t.Helper()
		var roleCount, receiptCount int64
		err := pool.QueryRow(ctx, `SELECT
           (SELECT count(*) FROM principal_role WHERE principal_id=$1),
           (SELECT count(*) FROM cat49_disposable_reviewer_grant WHERE principal_id=$1)`, in.PrincipalID).
			Scan(&roleCount, &receiptCount)
		if err != nil {
			t.Fatal("CAT49 SQL state read failed", err)
		}
		return roleCount, receiptCount
	}
	// Deliberately fail at the receipt constraint AFTER the role INSERT.
	// Production withTx must roll both back.
	bad := in
	bad.Operator = strings.Repeat("x", 65)
	if _, err := store.GrantCAT49Reviewer(ctx, bad); err == nil {
		t.Fatal("invalid receipt committed a role")
	}
	if roles, receipts := counts(); roles != 0 || receipts != 0 {
		t.Fatal("receipt failure committed a partial grant")
	}

	initial, err := store.GrantCAT49Reviewer(ctx, in)
	if err != nil || initial.Role != "moderator" || initial.RunID != owner.RunID {
		t.Fatalf("initial CAT49 grant: %v", err)
	}
	if roles, receipts := counts(); roles != 1 || receipts != 1 {
		t.Fatal("CAT49 role/receipt not atomic")
	}
	var roleXmin, receiptXmin string
	err = pool.QueryRow(ctx, `SELECT
       (SELECT xmin::text FROM principal_role WHERE principal_id=$1),
       (SELECT xmin::text FROM cat49_disposable_reviewer_grant WHERE principal_id=$1)`, in.PrincipalID).
		Scan(&roleXmin, &receiptXmin)
	if err != nil {
		t.Fatal("CAT49 SQL receipt revisions unavailable")
	}
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := store.GrantCAT49Reviewer(ctx, in)
			if err == nil && got != initial {
				err = errors.New("replay receipt mismatch")
			}
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent identical replay failed: %v", err)
		}
	}
	var roleXminAfter, receiptXminAfter string
	err = pool.QueryRow(ctx, `SELECT
       (SELECT xmin::text FROM principal_role WHERE principal_id=$1),
       (SELECT xmin::text FROM cat49_disposable_reviewer_grant WHERE principal_id=$1)`, in.PrincipalID).
		Scan(&roleXminAfter, &receiptXminAfter)
	if err != nil || roleXminAfter != roleXmin || receiptXminAfter != receiptXmin {
		t.Fatal("CAT49 replay rewrote durable state")
	}

	changed := []repository.CAT49ReviewerGrantIntent{}
	c := in
	c.AuthReceiptDigest = "sha256:" + strings.Repeat("b", 64)
	changed = append(changed, c)
	c = in
	c.Operator = "foreign-operator"
	changed = append(changed, c)
	c = in
	c.RequestID = signupSQLUUID(t)
	changed = append(changed, c)
	c = in
	c.PrincipalID = signupSQLUUID(t)
	changed = append(changed, c)
	c = in
	c.RequestID = signupSQLUUID(t)
	c.PrincipalID = signupSQLUUID(t)
	changed = append(changed, c)
	for _, candidate := range changed {
		if _, err := store.GrantCAT49Reviewer(ctx, candidate); err == nil {
			t.Fatal("changed CAT49 intent accepted")
		}
	}
	if roles, receipts := counts(); roles != 1 || receipts != 1 {
		t.Fatal("CAT49 conflict changed assignment or receipt count")
	}
	for _, sql := range []string{
		`UPDATE cat49_disposable_reviewer_grant SET operator_name=operator_name WHERE principal_id=$1`,
		`DELETE FROM cat49_disposable_reviewer_grant WHERE principal_id=$1`,
	} {
		if _, err := pool.Exec(ctx, sql, in.PrincipalID); err == nil {
			t.Fatal("immutable CAT49 receipt was changed")
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE principal_role SET role_id=(SELECT id FROM role WHERE key='student') WHERE principal_id=$1`, in.PrincipalID); err != nil {
		t.Fatal("CAT49 disposable role-drift fixture unavailable", err)
	}
	if _, err := store.GrantCAT49Reviewer(ctx, in); err == nil {
		t.Fatal("CAT49 exact replay silently repaired revoked role")
	}
	if roles, receipts := counts(); roles != 1 || receipts != 1 {
		t.Fatal("CAT49 drift replay changed durable receipt counts")
	}
	role, err := store.GetDefaultRole(ctx, in.PrincipalID)
	if err != nil || role != "student" {
		t.Fatalf("CAT49 drift not preserved: %q, %v", role, err)
	}
}
