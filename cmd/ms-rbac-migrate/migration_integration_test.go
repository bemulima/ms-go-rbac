package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/example/ms-rbac-service/internal/domain/model"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSchemaProfileFreshDatabaseAndMigrationContinuation(t *testing.T) {
	admin, adminDSN := migrationTestAdmin(t)
	ctx := context.Background()
	database := newMigrationTestDatabase(t, ctx, admin)
	pool := migrationTestPool(t, ctx, adminDSN, database)

	migrations := repositoryMigrations(t)
	futurePath := filepath.Join(t.TempDir(), "003_future_schema.sql")
	if err := os.WriteFile(futurePath, []byte("CREATE TABLE future_schema_probe (id integer PRIMARY KEY);\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	migrations = append(migrations, migration{version: "003_future_schema.sql", upPath: futurePath})

	current, err := inspect(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if err := apply(ctx, pool, current, migrations, profileSchema); err != nil {
		t.Fatalf("apply fresh schema profile: %v", err)
	}
	assertSchemaProfilePostconditions(t, ctx, pool)

	current, err = inspect(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if err := apply(ctx, pool, current, migrations, profileSchema); err != nil {
		t.Fatalf("repeat schema profile: %v", err)
	}
	assertSchemaProfilePostconditions(t, ctx, pool)

	failurePath := filepath.Join(t.TempDir(), "004_broken_schema.sql")
	if err := os.WriteFile(failurePath, []byte("CREATE TABLE failed_schema_probe (id integer PRIMARY KEY);\nSELECT * FROM missing_schema_probe;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	withFailure := append(append([]migration(nil), migrations...), migration{version: "004_broken_schema.sql", upPath: failurePath})
	current, err = inspect(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if err := apply(ctx, pool, current, withFailure, profileSchema); err == nil || !strings.Contains(err.Error(), "004_broken_schema.sql") {
		t.Fatalf("broken migration error = %v, want a fail-fast 004_broken_schema.sql error", err)
	}
	var failedTableExists, failedMigrationRecorded bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('public.failed_schema_probe') IS NOT NULL, EXISTS (SELECT 1 FROM rbac_schema_migrations WHERE version = '004_broken_schema.sql')`).Scan(&failedTableExists, &failedMigrationRecorded); err != nil {
		t.Fatal(err)
	}
	if failedTableExists || failedMigrationRecorded {
		t.Fatalf("failed migration rollback: table=%t ledger=%t; want both false", failedTableExists, failedMigrationRecorded)
	}

	if _, err := pool.Exec(ctx, `UPDATE role SET title = 'drift' WHERE key = 'student'`); err != nil {
		t.Fatal(err)
	}
	if err := ensureReferenceData(ctx, pool); err == nil || !strings.Contains(err.Error(), `canonical role "student" title mismatch`) {
		t.Fatalf("reference bootstrap error = %v, want a student title drift failure", err)
	}
}

func TestExplicitLegacyProfileStillCreatesItsHistoricalAssignments(t *testing.T) {
	admin, adminDSN := migrationTestAdmin(t)
	ctx := context.Background()
	database := newMigrationTestDatabase(t, ctx, admin)
	pool := migrationTestPool(t, ctx, adminDSN, database)

	current, err := inspect(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if err := apply(ctx, pool, current, repositoryMigrations(t), profileLegacy); err != nil {
		t.Fatalf("apply explicit legacy profile: %v", err)
	}
	if err := ensureReferenceData(ctx, pool); err != nil {
		t.Fatalf("verify reference data after legacy profile: %v", err)
	}

	var roles, principals, assignments int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM role`).Scan(&roles); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(DISTINCT principal_id) FROM principal_role`).Scan(&principals); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM principal_role`).Scan(&assignments); err != nil {
		t.Fatal(err)
	}
	if roles != len(model.CanonicalRoles()) || principals != 7 || assignments != 7 {
		t.Fatalf("legacy seed rows: roles=%d principals=%d assignments=%d; want roles=%d, principals=7, assignments=7", roles, principals, assignments, len(model.CanonicalRoles()))
	}
}

func TestHistoricalSchemaAdoptionRecordsAndPreservesSeedDisposition(t *testing.T) {
	admin, adminDSN := migrationTestAdmin(t)
	ctx := context.Background()
	migrations := repositoryMigrations(t)

	t.Run("001-only is adopted as excluded and explicit legacy applies 002", func(t *testing.T) {
		database := newMigrationTestDatabase(t, ctx, admin)
		pool := migrationTestPool(t, ctx, adminDSN, database)
		installMigration(t, ctx, pool, baseSchemaMigration)
		if _, err := pool.Exec(ctx, `INSERT INTO role(key,title) VALUES ('application_custom_role','Application Custom Role')`); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO permission(action,resource_kind) VALUES ('application:custom','application')`); err != nil {
			t.Fatal(err)
		}

		current, err := inspect(ctx, pool)
		if err != nil {
			t.Fatal(err)
		}
		if err := apply(ctx, pool, current, migrations, profileSchema); err != nil {
			t.Fatalf("adopt 001-only schema: %v", err)
		}
		assertDisposition(t, ctx, pool, baseSchemaMigration, dispositionAdopted)
		assertDisposition(t, ctx, pool, legacyPrincipalSeed, dispositionExcluded)
		var customRole, customPermission int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM role WHERE key='application_custom_role'`).Scan(&customRole); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM permission WHERE action='application:custom'`).Scan(&customPermission); err != nil {
			t.Fatal(err)
		}
		if customRole != 1 || customPermission != 1 {
			t.Fatalf("unrelated application rows were not preserved: custom role=%d permission=%d", customRole, customPermission)
		}

		current, err = inspect(ctx, pool)
		if err != nil {
			t.Fatal(err)
		}
		if err := apply(ctx, pool, current, migrations, profileLegacy); err != nil {
			t.Fatalf("apply explicitly selected excluded 002: %v", err)
		}
		assertDisposition(t, ctx, pool, legacyPrincipalSeed, dispositionApplied)
		assertAssignmentCount(t, ctx, pool, 7)
	})

	for _, scenario := range []struct {
		name       string
		managerEra bool
		wantStatus migrationDisposition
	}{
		{name: "complete current 002", wantStatus: dispositionAdopted},
		{name: "complete manager-era 002", managerEra: true, wantStatus: dispositionAdoptedManager},
	} {
		scenario := scenario
		t.Run(scenario.name+" is adopted without replay", func(t *testing.T) {
			database := newMigrationTestDatabase(t, ctx, admin)
			pool := migrationTestPool(t, ctx, adminDSN, database)
			installMigration(t, ctx, pool, baseSchemaMigration)
			if scenario.managerEra {
				installManagerEraSeed(t, ctx, pool)
			} else {
				installMigration(t, ctx, pool, legacyPrincipalSeed)
			}

			current, err := inspect(ctx, pool)
			if err != nil {
				t.Fatal(err)
			}
			if err := apply(ctx, pool, current, migrations, profileSchema); err != nil {
				t.Fatalf("adopt historical 002 footprint: %v", err)
			}
			assertDisposition(t, ctx, pool, legacyPrincipalSeed, scenario.wantStatus)

			if _, err := pool.Exec(ctx, `DELETE FROM principal_role WHERE principal_id = '00000000-0000-0000-0000-0000000000a1'`); err != nil {
				t.Fatal(err)
			}
			current, err = inspect(ctx, pool)
			if err != nil {
				t.Fatal(err)
			}
			if err := apply(ctx, pool, current, migrations, profileLegacy); err != nil {
				t.Fatalf("explicit legacy profile after adoption: %v", err)
			}
			assertDisposition(t, ctx, pool, legacyPrincipalSeed, scenario.wantStatus)
			assertAssignmentCount(t, ctx, pool, 6)
		})
	}
}

func TestHistoricalAdoptionRefusesPartialOrUnknownFootprintsBeforeLedgerWrite(t *testing.T) {
	admin, adminDSN := migrationTestAdmin(t)
	ctx := context.Background()
	migrations := repositoryMigrations(t)
	for _, scenario := range []struct {
		name  string
		setup func(*testing.T, *pgxpool.Pool)
	}{
		{name: "partial canonical seed", setup: func(t *testing.T, pool *pgxpool.Pool) {
			if _, err := pool.Exec(context.Background(), `INSERT INTO role(key,title) VALUES ('admin','Admin')`); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "unexpected schema object", setup: func(t *testing.T, pool *pgxpool.Pool) {
			if _, err := pool.Exec(context.Background(), `CREATE TABLE application_owned_probe(id integer)`); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "wrong core identity", setup: func(t *testing.T, pool *pgxpool.Pool) {
			if _, err := pool.Exec(context.Background(), `INSERT INTO service(id,key,title) VALUES ('00000000-0000-0000-0000-000000000101','core','Core Service')`); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		scenario := scenario
		t.Run(scenario.name, func(t *testing.T) {
			database := newMigrationTestDatabase(t, ctx, admin)
			pool := migrationTestPool(t, ctx, adminDSN, database)
			installMigration(t, ctx, pool, baseSchemaMigration)
			scenario.setup(t, pool)

			current, err := inspect(ctx, pool)
			if err != nil {
				t.Fatal(err)
			}
			if err := apply(ctx, pool, current, migrations, profileSchema); err == nil {
				t.Fatal("apply succeeded for a partial or unsupported historical footprint")
			}
			var historyExists bool
			if err := pool.QueryRow(ctx, `SELECT to_regclass('public.rbac_schema_migrations') IS NOT NULL`).Scan(&historyExists); err != nil {
				t.Fatal(err)
			}
			if historyExists {
				t.Fatal("refusal wrote a migration ledger; want no write before adoption is proven")
			}
		})
	}
}

func TestPublicRewriteRulesAreRejectedBeforeAdoptionOrLedgerWrites(t *testing.T) {
	admin, adminDSN := migrationTestAdmin(t)
	ctx := context.Background()
	migrations := repositoryMigrations(t)

	t.Run("historical 001 rule blocks adoption until dropped", func(t *testing.T) {
		database := newMigrationTestDatabase(t, ctx, admin)
		pool := migrationTestPool(t, ctx, adminDSN, database)
		installMigration(t, ctx, pool, baseSchemaMigration)
		if _, err := pool.Exec(ctx, `CREATE RULE migration_adoption_probe AS ON UPDATE TO public.role DO INSTEAD NOTHING`); err != nil {
			t.Fatalf("create public role rewrite rule: %v", err)
		}

		current, err := inspect(ctx, pool)
		if err != nil {
			t.Fatal(err)
		}
		if err := apply(ctx, pool, current, migrations, profileSchema); err == nil || !strings.Contains(err.Error(), "rewrite rule") {
			t.Fatalf("adopt schema with public rewrite rule: error=%v, want rewrite-rule refusal", err)
		}
		var historyExists bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass('public.rbac_schema_migrations') IS NOT NULL`).Scan(&historyExists); err != nil {
			t.Fatal(err)
		}
		if historyExists {
			t.Fatal("rewrite-rule refusal wrote a migration ledger")
		}

		if _, err := pool.Exec(ctx, `DROP RULE migration_adoption_probe ON public.role`); err != nil {
			t.Fatalf("drop public role rewrite rule: %v", err)
		}
		current, err = inspect(ctx, pool)
		if err != nil {
			t.Fatal(err)
		}
		if err := apply(ctx, pool, current, migrations, profileSchema); err != nil {
			t.Fatalf("adopt canonical historical 001 after dropping rewrite rule: %v", err)
		}
		assertDisposition(t, ctx, pool, baseSchemaMigration, dispositionAdopted)
	})

	t.Run("view generated return rule is rejected before fresh ledger creation", func(t *testing.T) {
		database := newMigrationTestDatabase(t, ctx, admin)
		pool := migrationTestPool(t, ctx, adminDSN, database)
		if _, err := pool.Exec(ctx, `CREATE VIEW public.adoption_probe AS SELECT 1 AS id`); err != nil {
			t.Fatalf("create public view: %v", err)
		}
		var returnRuleExists bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM pg_rewrite r
			JOIN pg_class c ON c.oid = r.ev_class
			JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = 'public' AND c.relname = 'adoption_probe' AND r.rulename = '_RETURN'
		)`).Scan(&returnRuleExists); err != nil {
			t.Fatal(err)
		}
		if !returnRuleExists {
			t.Fatal("public view did not expose its generated _RETURN rewrite rule")
		}

		current, err := inspect(ctx, pool)
		if err != nil {
			t.Fatal(err)
		}
		if err := apply(ctx, pool, current, migrations, profileSchema); err == nil || !strings.Contains(err.Error(), "rewrite rule") {
			t.Fatalf("apply to database with public view: error=%v, want rewrite-rule refusal", err)
		}
		var historyExists bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass('public.rbac_schema_migrations') IS NOT NULL`).Scan(&historyExists); err != nil {
			t.Fatal(err)
		}
		if historyExists {
			t.Fatal("view rewrite-rule refusal wrote a migration ledger")
		}
	})

	t.Run("ledger-only database rule blocks migration ledger writes", func(t *testing.T) {
		database := newMigrationTestDatabase(t, ctx, admin)
		pool := migrationTestPool(t, ctx, adminDSN, database)
		if _, err := pool.Exec(ctx, `CREATE TABLE public.rbac_schema_migrations (
			version text PRIMARY KEY,
			disposition text NOT NULL CHECK (disposition IN ('applied','adopted-applied','adopted-manager-era','excluded')),
			applied_at timestamptz NOT NULL DEFAULT now()
		)`); err != nil {
			t.Fatalf("create empty migration ledger: %v", err)
		}
		if _, err := pool.Exec(ctx, `CREATE RULE migration_ledger_probe AS ON UPDATE TO public.rbac_schema_migrations DO INSTEAD NOTHING`); err != nil {
			t.Fatalf("create public ledger rewrite rule: %v", err)
		}

		current, err := inspect(ctx, pool)
		if err != nil {
			t.Fatal(err)
		}
		if err := apply(ctx, pool, current, migrations, profileSchema); err == nil || !strings.Contains(err.Error(), "rewrite rule") {
			t.Fatalf("apply to ledger-only database with public rewrite rule: error=%v, want rewrite-rule refusal", err)
		}
		var ledgerRows int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM public.rbac_schema_migrations`).Scan(&ledgerRows); err != nil {
			t.Fatal(err)
		}
		if ledgerRows != 0 {
			t.Fatalf("rewrite-rule refusal wrote %d migration ledger row(s), want none", ledgerRows)
		}
	})
}

func TestFreshClassificationRejectsPublicTextSearchObjects(t *testing.T) {
	admin, adminDSN := migrationTestAdmin(t)
	ctx := context.Background()
	database := newMigrationTestDatabase(t, ctx, admin)
	pool := migrationTestPool(t, ctx, adminDSN, database)
	if _, err := pool.Exec(ctx, `CREATE TEXT SEARCH CONFIGURATION public.adoption_probe (COPY = pg_catalog.simple)`); err != nil {
		t.Fatalf("create public text-search probe: %v", err)
	}

	current, err := inspect(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if err := apply(ctx, pool, current, repositoryMigrations(t), profileSchema); err == nil {
		t.Fatal("apply accepted a database with a public text-search object as fresh")
	}
	var historyExists bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('public.rbac_schema_migrations') IS NOT NULL`).Scan(&historyExists); err != nil {
		t.Fatal(err)
	}
	if historyExists {
		t.Fatal("fresh classification refusal wrote a migration ledger")
	}
}

func TestReferenceBootstrapRejectsCoreIDDrift(t *testing.T) {
	admin, adminDSN := migrationTestAdmin(t)
	ctx := context.Background()
	database := newMigrationTestDatabase(t, ctx, admin)
	pool := migrationTestPool(t, ctx, adminDSN, database)
	current, err := inspect(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if err := apply(ctx, pool, current, repositoryMigrations(t), profileSchema); err != nil {
		t.Fatalf("apply schema profile: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE service SET id = '00000000-0000-0000-0000-000000000101' WHERE key = 'core'`); err != nil {
		t.Fatal(err)
	}
	if err := ensureReferenceData(ctx, pool); err == nil || !strings.Contains(err.Error(), `canonical service "core" id mismatch`) {
		t.Fatalf("reference bootstrap error = %v, want a core ID drift failure", err)
	}
}

func TestRollbackUsesOneLockedSessionAndFailureIsAtomic(t *testing.T) {
	admin, adminDSN := migrationTestAdmin(t)
	ctx := context.Background()

	t.Run("serialization and session continuity", func(t *testing.T) {
		database := newMigrationTestDatabase(t, ctx, admin)
		pool := migrationTestPool(t, ctx, adminDSN, database)
		migrations := repositoryMigrations(t)
		upPath := filepath.Join(t.TempDir(), "003_rollback_probe.up.sql")
		downPath := filepath.Join(t.TempDir(), "003_rollback_probe.down.sql")
		writeSQLFile(t, upPath, `CREATE TABLE rollback_probe(id integer PRIMARY KEY);`)
		writeSQLFile(t, downPath, `SELECT pg_advisory_lock(123456789, 987654321); SELECT pg_sleep(1.2); SELECT pg_advisory_unlock(123456789, 987654321); DROP TABLE rollback_probe;`)
		migrations = append(migrations, migration{version: "003_rollback_probe.up.sql", upPath: upPath, downPath: downPath})
		current, err := inspect(ctx, pool)
		if err != nil {
			t.Fatal(err)
		}
		if err := apply(ctx, pool, current, migrations, profileSchema); err != nil {
			t.Fatalf("apply rollback probe: %v", err)
		}
		current, err = inspect(ctx, pool)
		if err != nil {
			t.Fatal(err)
		}

		firstDone := make(chan error, 1)
		go func() { firstDone <- rollback(ctx, pool, current, migrations) }()
		pid := waitForAdvisoryMarker(t, ctx, pool)
		var lockCount int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND pid = $1 AND granted`, pid).Scan(&lockCount); err != nil {
			t.Fatal(err)
		}
		if lockCount < 2 {
			t.Fatalf("rollback backend %d holds %d advisory locks; want migration and SQL marker locks on one session", pid, lockCount)
		}

		secondDone := make(chan error, 1)
		go func() { secondDone <- rollback(ctx, pool, current, migrations) }()
		select {
		case err := <-secondDone:
			t.Fatalf("second rollback returned while the first held its marker lock: %v", err)
		case <-time.After(150 * time.Millisecond):
		}
		if err := <-firstDone; err != nil {
			t.Fatalf("first rollback: %v", err)
		}
		if err := <-secondDone; err != nil {
			t.Fatalf("serialized second rollback: %v", err)
		}
	})

	t.Run("SQL failure rolls back ledger and releases lock", func(t *testing.T) {
		database := newMigrationTestDatabase(t, ctx, admin)
		pool := migrationTestPool(t, ctx, adminDSN, database)
		migrations := repositoryMigrations(t)
		upPath := filepath.Join(t.TempDir(), "003_rollback_failure.up.sql")
		downPath := filepath.Join(t.TempDir(), "003_rollback_failure.down.sql")
		writeSQLFile(t, upPath, `CREATE TABLE rollback_failure_probe(id integer PRIMARY KEY);`)
		writeSQLFile(t, downPath, `CREATE TABLE rollback_failure_side_effect(id integer); SELECT * FROM rollback_failure_missing_table;`)
		migrations = append(migrations, migration{version: "003_rollback_failure.up.sql", upPath: upPath, downPath: downPath})
		current, err := inspect(ctx, pool)
		if err != nil {
			t.Fatal(err)
		}
		if err := apply(ctx, pool, current, migrations, profileSchema); err != nil {
			t.Fatalf("apply rollback failure probe: %v", err)
		}
		current, err = inspect(ctx, pool)
		if err != nil {
			t.Fatal(err)
		}
		if err := rollback(ctx, pool, current, migrations); err == nil {
			t.Fatal("rollback unexpectedly succeeded despite invalid down SQL")
		}
		var sideEffectExists, migrationRecorded bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass('public.rollback_failure_side_effect') IS NOT NULL, EXISTS(SELECT 1 FROM rbac_schema_migrations WHERE version = '003_rollback_failure.up.sql')`).Scan(&sideEffectExists, &migrationRecorded); err != nil {
			t.Fatal(err)
		}
		if sideEffectExists || !migrationRecorded {
			t.Fatalf("failed rollback atomicity: side effect=%t migration ledger row=%t; want false,true", sideEffectExists, migrationRecorded)
		}
		lockConn, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer lockConn.Release()
		var lockAcquired bool
		if err := lockConn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtext($1))`, migrationLockKey).Scan(&lockAcquired); err != nil {
			t.Fatal(err)
		}
		if !lockAcquired {
			t.Fatal("migration lock remained held after failed rollback")
		}
		var unlocked bool
		if err := lockConn.QueryRow(ctx, `SELECT pg_advisory_unlock(hashtext($1))`, migrationLockKey).Scan(&unlocked); err != nil || !unlocked {
			t.Fatalf("release test migration lock: unlocked=%t err=%v", unlocked, err)
		}
	})
}

func installMigration(t *testing.T, ctx context.Context, pool *pgxpool.Pool, version string) {
	t.Helper()
	var path string
	for _, item := range repositoryMigrations(t) {
		if item.version == version {
			path = item.upPath
			break
		}
	}
	if path == "" {
		t.Fatalf("repository migration %s not found", version)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err := conn.Conn().PgConn().Exec(ctx, "BEGIN;\n"+string(contents)+"\nCOMMIT;").ReadAll(); err != nil {
		t.Fatalf("install historical migration %s: %v", version, err)
	}
}

func installManagerEraSeed(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	for _, role := range managerSeedRoles {
		if _, err := pool.Exec(ctx, `INSERT INTO role(key,title) VALUES ($1,$2)`, role.key, role.title); err != nil {
			t.Fatalf("insert manager-era role %q: %v", role.key, err)
		}
	}
	service := model.CanonicalCoreService()
	if _, err := pool.Exec(ctx, `INSERT INTO service(id,key,title) VALUES ($1,$2,$3)`, service.ID, service.Key, service.Title); err != nil {
		t.Fatalf("insert manager-era core service: %v", err)
	}
	for _, grant := range managerSeedGrants {
		if _, err := pool.Exec(ctx, `INSERT INTO principal_role(principal_id,principal_kind,role_id,tenant_id,service_id,resource_kind,resource_id)
			SELECT $1::uuid,'user',r.id,'00000000-0000-0000-0000-000000000000'::uuid,s.id,'global','00000000-0000-0000-0000-000000000000'::uuid
			FROM role r CROSS JOIN service s WHERE r.key=$2 AND s.key='core'`, grant.principal, grant.role); err != nil {
			t.Fatalf("insert manager-era assignment %s: %v", grant.principal, err)
		}
	}
}

func assertDisposition(t *testing.T, ctx context.Context, pool *pgxpool.Pool, version string, want migrationDisposition) {
	t.Helper()
	var got migrationDisposition
	if err := pool.QueryRow(ctx, `SELECT disposition FROM rbac_schema_migrations WHERE version=$1`, version).Scan(&got); err != nil {
		t.Fatalf("read disposition for %s: %v", version, err)
	}
	if got != want {
		t.Fatalf("migration %s disposition=%q, want %q", version, got, want)
	}
}

func assertAssignmentCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, want int) {
	t.Helper()
	var got int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM principal_role`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("principal assignment count=%d, want %d", got, want)
	}
}

func writeSQLFile(t *testing.T, path, sql string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(sql+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func waitForAdvisoryMarker(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int32 {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var pid int32
		err := pool.QueryRow(ctx, `SELECT pid FROM pg_locks WHERE locktype='advisory' AND classid=123456789::oid AND objid=987654321::oid AND objsubid=2 AND granted`).Scan(&pid)
		if err == nil {
			return pid
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timed out waiting for rollback down SQL advisory marker")
	return 0
}

func migrationTestAdmin(t *testing.T) (*pgx.Conn, string) {
	t.Helper()
	dsn := os.Getenv("RBAC_MIGRATION_TEST_ADMIN_DSN")
	if dsn == "" {
		t.Skip("RBAC_MIGRATION_TEST_ADMIN_DSN is not set; isolated PostgreSQL migration tests are opt-in")
	}
	if os.Getenv("RBAC_MIGRATION_TEST_ALLOW_CREATE_DATABASE") != "YES" {
		t.Fatal("set RBAC_MIGRATION_TEST_ALLOW_CREATE_DATABASE=YES only for an isolated disposable PostgreSQL instance")
	}

	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse isolated PostgreSQL DSN: %v", err)
	}
	if config.Host != "127.0.0.1" && config.Host != "localhost" && config.Host != "::1" {
		t.Fatalf("migration integration tests require loopback PostgreSQL, got host %q", config.Host)
	}
	if config.Database != "postgres" {
		t.Fatalf("migration integration tests require the disposable server's postgres database, got %q", config.Database)
	}

	conn, err := pgx.ConnectConfig(context.Background(), config)
	if err != nil {
		t.Fatalf("connect to isolated PostgreSQL: %v", err)
	}
	var database, user string
	var superuser bool
	if err := conn.QueryRow(context.Background(), `SELECT current_database(), current_user, r.rolsuper FROM pg_roles r WHERE r.rolname = current_user`).Scan(&database, &user, &superuser); err != nil {
		_ = conn.Close(context.Background())
		t.Fatalf("inspect isolated PostgreSQL identity: %v", err)
	}
	if database != "postgres" || !superuser {
		_ = conn.Close(context.Background())
		t.Fatalf("migration integration tests require the isolated postgres superuser database, got database=%q user=%q superuser=%t", database, user, superuser)
	}
	t.Cleanup(func() {
		if err := conn.Close(context.Background()); err != nil {
			t.Errorf("close isolated PostgreSQL admin connection: %v", err)
		}
	})
	return conn, dsn
}

func newMigrationTestDatabase(t *testing.T, ctx context.Context, admin *pgx.Conn) string {
	t.Helper()
	var random [6]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	name := "rbac_migration_test_" + hex.EncodeToString(random[:])
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create isolated migration test database: %v", err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)"); err != nil {
			t.Errorf("drop isolated migration test database %s: %v", name, err)
		}
	})
	return name
}

func migrationTestPool(t *testing.T, ctx context.Context, adminDSN, database string) *pgxpool.Pool {
	t.Helper()
	config, err := pgxpool.ParseConfig(adminDSN)
	if err != nil {
		t.Fatalf("parse isolated migration test pool configuration: %v", err)
	}
	config.ConnConfig.Database = database
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("connect to isolated migration test database: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func repositoryMigrations(t *testing.T) []migration {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate migration integration test source")
	}
	directory := filepath.Join(filepath.Dir(source), "..", "..", "migrations")
	migrations, err := discoverMigrations(directory)
	if err != nil {
		t.Fatalf("discover repository migrations: %v", err)
	}
	return migrations
}

func assertSchemaProfilePostconditions(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	var roleCount, principalCount, assignmentCount, futureTableCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM role`).Scan(&roleCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM (
		SELECT principal_id FROM principal_role
		UNION SELECT principal_id FROM principal_override
		UNION SELECT principal_id FROM superadmin_principal
	) AS principals`).Scan(&principalCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM principal_role`).Scan(&assignmentCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_tables WHERE schemaname = 'public' AND tablename = 'future_schema_probe'`).Scan(&futureTableCount); err != nil {
		t.Fatal(err)
	}
	if roleCount != len(model.CanonicalRoles()) || principalCount != 0 || assignmentCount != 0 || futureTableCount != 1 {
		t.Fatalf("schema profile postconditions: roles=%d principals=%d assignments=%d future_schema_probe=%d; want roles=%d, principals=0, assignments=0, future_schema_probe=1", roleCount, principalCount, assignmentCount, futureTableCount, len(model.CanonicalRoles()))
	}
	for _, expected := range model.CanonicalRoles() {
		var actualTitle string
		if err := pool.QueryRow(ctx, `SELECT title FROM role WHERE key = $1`, expected.Key).Scan(&actualTitle); err != nil {
			t.Fatalf("read canonical role %q: %v", expected.Key, err)
		}
		if actualTitle != expected.Title {
			t.Errorf("canonical role %q title = %q, want %q", expected.Key, actualTitle, expected.Title)
		}
	}

	var coreCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM service WHERE key = 'core' AND title = 'Core Service'`).Scan(&coreCount); err != nil {
		t.Fatal(err)
	}
	if coreCount != 1 {
		t.Fatalf("canonical core service rows = %d, want 1", coreCount)
	}

	var baseDisposition, legacyDisposition, futureDisposition migrationDisposition
	if err := pool.QueryRow(ctx, `SELECT
		(SELECT disposition FROM rbac_schema_migrations WHERE version = $1),
		(SELECT disposition FROM rbac_schema_migrations WHERE version = $2),
		(SELECT disposition FROM rbac_schema_migrations WHERE version = $3)`, baseSchemaMigration, legacyPrincipalSeed, "003_future_schema.sql").Scan(&baseDisposition, &legacyDisposition, &futureDisposition); err != nil {
		t.Fatal(err)
	}
	if baseDisposition != dispositionApplied || legacyDisposition != dispositionExcluded || futureDisposition != dispositionApplied {
		t.Fatalf("migration ledger dispositions: base=%q legacy=%q future=%q; want %q,%q,%q", baseDisposition, legacyDisposition, futureDisposition, dispositionApplied, dispositionExcluded, dispositionApplied)
	}
}
