// Command ms-rbac-migrate applies the repository SQL migrations through DB_DSN.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/example/ms-rbac-service/internal/domain/model"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const migrationTable = "rbac_schema_migrations"

const (
	baseSchemaMigration = "001_init.sql"
	// Freeze the current contents of this legacy migration; prior Git history
	// contains a manager-era revision and must remain distinguishable on adoption.
	legacyPrincipalSeed  = "002_seed_default_roles_and_principals.up.sql"
	referenceDataLockKey = "ms-go-rbac-reference-data"
	migrationLockKey     = "ms-go-rbac-migrations"
)

type migrationDisposition string

const (
	dispositionApplied        migrationDisposition = "applied"
	dispositionAdopted        migrationDisposition = "adopted-applied"
	dispositionAdoptedManager migrationDisposition = "adopted-manager-era"
	dispositionExcluded       migrationDisposition = "excluded"
)

type migrationProfile string

const (
	profileSchema migrationProfile = "schema"
	profileLegacy migrationProfile = "legacy"
)

type migration struct {
	version  string
	upPath   string
	downPath string
}

type state struct {
	database        string
	role            string
	superuser       bool
	historyExists   bool
	historyHasState bool
	tableCount      int
	applied         map[string]bool
	dispositions    map[string]migrationDisposition
}

func main() {
	action := "status"
	if len(os.Args) > 1 {
		action = os.Args[1]
	}
	if action != "status" && action != "status-legacy" && action != "up" && action != "up-with-legacy-fixtures" && action != "down" {
		log.Fatalf("usage: ms-rbac-migrate [status|status-legacy|up|up-with-legacy-fixtures|down]")
	}

	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		log.Fatal("DB_DSN is required")
	}
	migrations, err := discoverMigrations("migrations")
	if err != nil {
		log.Fatalf("discover migrations: %v", err)
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		log.Fatalf("connect PostgreSQL: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		log.Fatalf("ping PostgreSQL: %v", err)
	}

	current, err := inspect(ctx, pool)
	if err != nil {
		log.Fatalf("inspect migration state: %v", err)
	}

	switch action {
	case "status":
		printStatus(current, migrations, profileSchema)
	case "status-legacy":
		printStatus(current, migrations, profileLegacy)
	case "up":
		if err := apply(ctx, pool, current, migrations, profileSchema); err != nil {
			log.Fatalf("apply migrations: %v", err)
		}
		current, err = inspect(ctx, pool)
		if err != nil {
			log.Fatalf("inspect migration state after apply: %v", err)
		}
		printStatus(current, migrations, profileSchema)
	case "up-with-legacy-fixtures":
		if err := apply(ctx, pool, current, migrations, profileLegacy); err != nil {
			log.Fatalf("apply legacy migrations: %v", err)
		}
		if err := ensureReferenceData(ctx, pool); err != nil {
			log.Fatalf("verify reference data after legacy migrations: %v", err)
		}
		current, err = inspect(ctx, pool)
		if err != nil {
			log.Fatalf("inspect migration state after apply: %v", err)
		}
		printStatus(current, migrations, profileLegacy)
	case "down":
		if err := rollback(ctx, pool, current, migrations); err != nil {
			log.Fatalf("rollback migrations: %v", err)
		}
		current, err = inspect(ctx, pool)
		if err != nil {
			log.Fatalf("inspect migration state after rollback: %v", err)
		}
		printStatus(current, migrations, profileLegacy)
	}
}

func discoverMigrations(directory string) ([]migration, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}

	byVersion := make(map[string]migration)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".sql") || strings.HasSuffix(name, ".down.sql") {
			continue
		}
		item := migration{version: name, upPath: filepath.Join(directory, name)}
		if strings.HasSuffix(name, ".up.sql") {
			item.downPath = filepath.Join(directory, strings.TrimSuffix(name, ".up.sql")+".down.sql")
		}
		if _, exists := byVersion[item.version]; exists {
			return nil, fmt.Errorf("duplicate migration version %q", item.version)
		}
		byVersion[item.version] = item
	}

	migrations := make([]migration, 0, len(byVersion))
	for _, item := range byVersion {
		migrations = append(migrations, item)
	}
	sort.Slice(migrations, func(i, j int) bool { return migrations[i].version < migrations[j].version })
	if len(migrations) == 0 {
		return nil, errors.New("no forward migrations found")
	}
	return migrations, nil
}

func inspect(ctx context.Context, pool *pgxpool.Pool) (state, error) {
	return inspectWith(ctx, pool)
}

func inspectWith(ctx context.Context, q catalogReader) (state, error) {
	current := state{applied: make(map[string]bool), dispositions: make(map[string]migrationDisposition)}
	if err := q.QueryRow(ctx, "SELECT current_database(), current_user, r.rolsuper FROM pg_roles r WHERE r.rolname = current_user").Scan(&current.database, &current.role, &current.superuser); err != nil {
		return state{}, err
	}
	if err := q.QueryRow(ctx, "SELECT to_regclass('public."+migrationTable+"') IS NOT NULL").Scan(&current.historyExists); err != nil {
		return state{}, err
	}
	if err := q.QueryRow(ctx, "SELECT count(*) FROM pg_tables WHERE schemaname = 'public' AND tablename <> $1", migrationTable).Scan(&current.tableCount); err != nil {
		return state{}, err
	}
	if !current.historyExists {
		return current, nil
	}
	if err := q.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = $1 AND column_name = 'disposition'
	)`, migrationTable).Scan(&current.historyHasState); err != nil {
		return state{}, err
	}
	query := "SELECT version FROM " + migrationTable + " ORDER BY version"
	if current.historyHasState {
		query = "SELECT version, disposition FROM " + migrationTable + " ORDER BY version"
	}
	rows, err := q.Query(ctx, query)
	if err != nil {
		return state{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var version string
		var disposition migrationDisposition
		if current.historyHasState {
			err = rows.Scan(&version, &disposition)
		} else {
			err = rows.Scan(&version)
			disposition = dispositionApplied
		}
		if err != nil {
			return state{}, err
		}
		current.dispositions[version] = disposition
		current.applied[version] = disposition != dispositionExcluded
	}
	return current, rows.Err()
}

func apply(ctx context.Context, pool *pgxpool.Pool, current state, migrations []migration, profile migrationProfile) (retErr error) {
	selected, err := migrationsForProfile(migrations, profile)
	if err != nil {
		return err
	}
	if profile == profileSchema && !hasMigration(selected, baseSchemaMigration) {
		return fmt.Errorf("schema profile requires %s", baseSchemaMigration)
	}

	lockConn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	locked := false
	connectionSafe := true
	defer func() {
		if err := releaseMigrationLock(lockConn, locked, connectionSafe); err != nil {
			retErr = errors.Join(retErr, err)
		}
	}()
	if _, err := lockConn.Exec(ctx, "SELECT pg_advisory_lock(hashtext($1))", migrationLockKey); err != nil {
		connectionSafe = false
		return err
	}
	locked = true

	current, err = inspectWith(ctx, lockConn)
	if err != nil {
		return fmt.Errorf("refresh migration state under lock: %w", err)
	}
	current, err = prepareMigrationHistory(ctx, lockConn, current, migrations)
	if err != nil {
		return err
	}

	if current.applied[baseSchemaMigration] {
		if err := ensureReferenceDataWith(ctx, lockConn.Conn()); err != nil {
			return fmt.Errorf("ensure reference data before pending migrations: %w", err)
		}
	}

	for _, item := range migrations {
		disposition, recorded := current.dispositions[item.version]
		if item.version == legacyPrincipalSeed && profile == profileSchema {
			if !recorded {
				current, err = resolveLegacyDisposition(ctx, lockConn, current, migrations)
				if err != nil {
					return err
				}
				disposition, recorded = current.dispositions[item.version]
			}
			if !recorded {
				if err := recordDisposition(ctx, lockConn, item.version, dispositionExcluded); err != nil {
					return err
				}
				current.dispositions[item.version] = dispositionExcluded
			}
			continue
		}
		if !hasMigration(selected, item.version) {
			continue
		}
		if recorded && disposition != dispositionExcluded {
			continue
		}
		if recorded && item.version != legacyPrincipalSeed {
			return fmt.Errorf("migration %s has unsupported excluded disposition", item.version)
		}
		if item.version == legacyPrincipalSeed && !recorded {
			current, err = resolveLegacyDisposition(ctx, lockConn, current, migrations)
			if err != nil {
				return err
			}
			disposition, recorded = current.dispositions[item.version]
			if recorded && disposition != dispositionExcluded {
				continue
			}
		}
		contents, err := os.ReadFile(item.upPath)
		if err != nil {
			return err
		}
		if err := executeFileOn(ctx, lockConn.Conn(), string(contents), migrationRecordSQL(item.version, dispositionApplied)); err != nil {
			return fmt.Errorf("%s: %w", item.version, err)
		}
		current.applied[item.version] = true
		current.dispositions[item.version] = dispositionApplied
		fmt.Printf("applied %s\n", item.version)
		if item.version == baseSchemaMigration && profile == profileSchema {
			if profile == profileSchema && hasMigration(migrations, legacyPrincipalSeed) {
				if err := recordDisposition(ctx, lockConn, legacyPrincipalSeed, dispositionExcluded); err != nil {
					return err
				}
				current.dispositions[legacyPrincipalSeed] = dispositionExcluded
			}
			if err := ensureReferenceDataWith(ctx, lockConn.Conn()); err != nil {
				return fmt.Errorf("ensure reference data after %s: %w", baseSchemaMigration, err)
			}
		}
	}
	return nil
}

func hasMigration(migrations []migration, version string) bool {
	for _, item := range migrations {
		if item.version == version {
			return true
		}
	}
	return false
}

func migrationsForProfile(migrations []migration, profile migrationProfile) ([]migration, error) {
	if profile != profileSchema && profile != profileLegacy {
		return nil, fmt.Errorf("unsupported migration profile %q", profile)
	}
	if profile == profileLegacy {
		return append([]migration(nil), migrations...), nil
	}
	selected := make([]migration, 0, len(migrations))
	for _, item := range migrations {
		if item.version == legacyPrincipalSeed {
			continue
		}
		selected = append(selected, item)
	}
	return selected, nil
}

func ensureReferenceData(ctx context.Context, pool *pgxpool.Pool) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	return ensureReferenceDataInTx(ctx, tx)
}

func ensureReferenceDataWith(ctx context.Context, conn *pgx.Conn) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	return ensureReferenceDataInTx(ctx, tx)
}

func ensureReferenceDataInTx(ctx context.Context, tx pgx.Tx) error {
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtext($1))", referenceDataLockKey); err != nil {
		return err
	}

	for _, role := range model.CanonicalRoles() {
		if _, err := tx.Exec(ctx, `INSERT INTO role (key, title) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING`, role.Key, role.Title); err != nil {
			return fmt.Errorf("insert canonical role %q: %w", role.Key, err)
		}
		var actualTitle string
		if err := tx.QueryRow(ctx, `SELECT title FROM role WHERE key = $1`, role.Key).Scan(&actualTitle); err != nil {
			return fmt.Errorf("read canonical role %q: %w", role.Key, err)
		}
		if actualTitle != role.Title {
			return fmt.Errorf("canonical role %q title mismatch: database has %q, want %q", role.Key, actualTitle, role.Title)
		}
	}

	service := model.CanonicalCoreService()
	if _, err := tx.Exec(ctx, `INSERT INTO service (id, key, title) VALUES ($1, $2, $3) ON CONFLICT (key) DO NOTHING`, service.ID, service.Key, service.Title); err != nil {
		return fmt.Errorf("insert canonical service %q: %w", service.Key, err)
	}
	var actualID, actualTitle string
	if err := tx.QueryRow(ctx, `SELECT id::text, title FROM service WHERE key = $1`, service.Key).Scan(&actualID, &actualTitle); err != nil {
		return fmt.Errorf("read canonical service %q: %w", service.Key, err)
	}
	if actualID != service.ID {
		return fmt.Errorf("canonical service %q id mismatch: database has %q, want %q", service.Key, actualID, service.ID)
	}
	if actualTitle != service.Title {
		return fmt.Errorf("canonical service %q title mismatch: database has %q, want %q", service.Key, actualTitle, service.Title)
	}
	return tx.Commit(ctx)
}

func rollback(ctx context.Context, pool *pgxpool.Pool, current state, migrations []migration) (retErr error) {
	lockConn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	locked := false
	connectionSafe := true
	defer func() {
		if err := releaseMigrationLock(lockConn, locked, connectionSafe); err != nil {
			retErr = errors.Join(retErr, err)
		}
	}()
	if _, err := lockConn.Exec(ctx, "SELECT pg_advisory_lock(hashtext($1))", migrationLockKey); err != nil {
		connectionSafe = false
		return err
	}
	locked = true
	current, err = inspectWith(ctx, lockConn)
	if err != nil {
		return fmt.Errorf("refresh rollback state under lock: %w", err)
	}
	if !current.historyExists {
		return errors.New("migration history disappeared; refusing rollback")
	}
	if !current.historyHasState {
		current, err = prepareMigrationHistory(ctx, lockConn, current, migrations)
		if err != nil {
			return err
		}
	}
	if err := validateLedgerForRollback(current, migrations); err != nil {
		return err
	}
	for index := len(migrations) - 1; index >= 0; index-- {
		item := migrations[index]
		disposition := current.dispositions[item.version]
		if !current.applied[item.version] || item.downPath == "" {
			continue
		}
		if item.version == legacyPrincipalSeed && disposition == dispositionAdoptedManager {
			return fmt.Errorf("refusing rollback of manager-era %s because the repository down migration describes the moderator-era seed", legacyPrincipalSeed)
		}
		contents, err := os.ReadFile(item.downPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		}
		if err := executeRollbackFile(ctx, lockConn.Conn(), string(contents), item.version); err != nil {
			return fmt.Errorf("%s: %w", item.version, err)
		}
		fmt.Printf("rolled back %s\n", item.version)
	}
	return nil
}

func executeFile(ctx context.Context, pool *pgxpool.Pool, sql, record string) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	return executeFileOn(ctx, conn.Conn(), sql, record)
}

func executeFileOn(ctx context.Context, conn *pgx.Conn, sql, record string) error {
	_, err := conn.PgConn().Exec(ctx, "BEGIN;\n"+sql+"\n"+record+";\nCOMMIT;").ReadAll()
	if err != nil {
		_, _ = conn.PgConn().Exec(ctx, "ROLLBACK;").ReadAll()
	}
	return err
}

func executeRollbackFile(ctx context.Context, conn *pgx.Conn, sql, version string) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Conn().PgConn().Exec(ctx, sql).ReadAll(); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM public.rbac_schema_migrations WHERE version = $1`, version); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func validateLedgerForRollback(current state, migrations []migration) error {
	if !current.historyExists || !current.historyHasState {
		return errors.New("rollback requires a validated migration ledger with dispositions")
	}
	if !current.applied[baseSchemaMigration] {
		return fmt.Errorf("rollback ledger does not record %s", baseSchemaMigration)
	}
	if err := requireSupportedMigrationVersions(current, migrations); err != nil {
		return err
	}
	for version, disposition := range current.dispositions {
		if !validDisposition(disposition) {
			return fmt.Errorf("invalid disposition %q for migration %s", disposition, version)
		}
		if disposition == dispositionExcluded && version != legacyPrincipalSeed {
			return fmt.Errorf("only %s may be excluded", legacyPrincipalSeed)
		}
	}
	return nil
}

func releaseMigrationLock(conn *pgxpool.Conn, locked, connectionSafe bool) error {
	if !connectionSafe {
		closePooledConnection(conn)
		return errors.New("migration connection was discarded after an uncertain lock operation")
	}
	if locked {
		var unlocked bool
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := conn.QueryRow(unlockCtx, "SELECT pg_advisory_unlock(hashtext($1))", migrationLockKey).Scan(&unlocked)
		cancel()
		if err != nil || !unlocked {
			closePooledConnection(conn)
			if err != nil {
				return fmt.Errorf("unlock migration session: %w; connection discarded", err)
			}
			return errors.New("migration session lock was not held at unlock; connection discarded")
		}
	}
	conn.Release()
	return nil
}

func closePooledConnection(conn *pgxpool.Conn) {
	if conn == nil {
		return
	}
	_ = conn.Hijack().Close(context.Background())
}

func quote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func printStatus(current state, migrations []migration, profile migrationProfile) {
	history := "absent"
	if current.historyExists {
		history = "present"
	}
	fmt.Printf("database=%s role=%s superuser=%t public_tables=%d migration_history=%s profile=%s\n", current.database, current.role, current.superuser, current.tableCount, history, profile)
	for _, item := range migrations {
		status := "pending"
		if disposition, exists := current.dispositions[item.version]; exists {
			switch disposition {
			case dispositionApplied:
				status = "applied"
			case dispositionAdopted:
				status = "adopted-applied"
			case dispositionAdoptedManager:
				status = "adopted-manager-era-applied"
			case dispositionExcluded:
				status = "intentionally-excluded"
			}
		} else if current.historyExists && item.version == legacyPrincipalSeed && current.applied[baseSchemaMigration] {
			status = "unresolved"
		} else if !current.historyExists && item.version == legacyPrincipalSeed && profile == profileSchema {
			status = "will-be-excluded"
		}
		fmt.Printf("%s %s\n", status, item.version)
	}
}
