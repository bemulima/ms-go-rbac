package main

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func prepareMigrationHistory(ctx context.Context, conn *pgxpool.Conn, current state, migrations []migration) (state, error) {
	known := make(map[string]bool, len(migrations))
	for _, item := range migrations {
		known[item.version] = true
	}
	for version, disposition := range current.dispositions {
		if !known[version] {
			return state{}, fmt.Errorf("migration ledger contains unknown version %q", version)
		}
		if !validDisposition(disposition) {
			return state{}, fmt.Errorf("migration ledger contains unknown disposition %q for %s", disposition, version)
		}
		if disposition == dispositionExcluded && version != legacyPrincipalSeed {
			return state{}, fmt.Errorf("only %s may have excluded disposition", legacyPrincipalSeed)
		}
	}

	if current.historyExists && !current.historyHasState {
		if err := upgradeLegacyHistory(ctx, conn, current, migrations); err != nil {
			return state{}, err
		}
		return inspectWith(ctx, conn)
	}

	if !current.historyExists {
		class, err := classifyApplicationSchema(ctx, conn)
		if err != nil {
			return state{}, fmt.Errorf("classify untracked schema: %w", err)
		}
		switch class {
		case schemaFresh:
			if err := createMigrationHistory(ctx, conn, nil); err != nil {
				return state{}, err
			}
		case schemaHistorical:
			if err := adoptUntrackedSchema(ctx, conn, migrations); err != nil {
				return state{}, err
			}
		default:
			return state{}, fmt.Errorf("refusing untracked schema that is neither fresh nor an exact migration 001 schema")
		}
		return inspectWith(ctx, conn)
	}

	if len(current.dispositions) == 0 {
		class, err := classifyApplicationSchema(ctx, conn)
		if err != nil {
			return state{}, fmt.Errorf("classify empty migration ledger: %w", err)
		}
		switch class {
		case schemaFresh:
			return current, nil
		case schemaHistorical:
			if err := adoptIntoEmptyHistory(ctx, conn, migrations); err != nil {
				return state{}, err
			}
			return inspectWith(ctx, conn)
		default:
			return state{}, fmt.Errorf("refusing empty migration ledger with an unsupported schema")
		}
	}

	if !current.applied[baseSchemaMigration] {
		return state{}, fmt.Errorf("migration ledger has entries but does not record %s", baseSchemaMigration)
	}
	if _, exists := current.dispositions[legacyPrincipalSeed]; !exists {
		return resolveLegacyDisposition(ctx, conn, current, migrations)
	}
	return current, nil
}

func upgradeLegacyHistory(ctx context.Context, conn *pgxpool.Conn, current state, migrations []migration) error {
	if !current.applied[baseSchemaMigration] {
		return fmt.Errorf("refusing legacy migration ledger without recorded %s", baseSchemaMigration)
	}
	if err := requireSupportedMigrationVersions(current, migrations); err != nil {
		return err
	}
	if err := verifyMigration001Catalog(ctx, conn); err != nil {
		return fmt.Errorf("refusing legacy ledger with noncanonical schema: %w", err)
	}
	seed, err := classifySeedFootprint(ctx, conn)
	if err != nil {
		return err
	}
	legacyApplied := current.applied[legacyPrincipalSeed]
	if legacyApplied && seed != seedCurrent && seed != seedManager {
		return fmt.Errorf("legacy ledger records %s applied but its seed footprint is not a complete supported version", legacyPrincipalSeed)
	}
	if !legacyApplied && seed == seedAmbiguous {
		return fmt.Errorf("legacy ledger has an ambiguous %s footprint; refusing history upgrade", legacyPrincipalSeed)
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `ALTER TABLE public.rbac_schema_migrations ADD COLUMN disposition text NOT NULL DEFAULT 'applied'`); err != nil {
		return fmt.Errorf("add migration disposition: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE public.rbac_schema_migrations SET disposition = $1 WHERE version = $2`, dispositionApplied, baseSchemaMigration); err != nil {
		return err
	}
	if legacyApplied {
		if _, err := tx.Exec(ctx, `UPDATE public.rbac_schema_migrations SET disposition = $1 WHERE version = $2`, seedDisposition(seed), legacyPrincipalSeed); err != nil {
			return err
		}
	} else {
		if _, err := tx.Exec(ctx, `INSERT INTO public.rbac_schema_migrations(version, disposition) VALUES ($1, $2)`, legacyPrincipalSeed, seedDisposition(seed)); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func adoptUntrackedSchema(ctx context.Context, conn *pgxpool.Conn, migrations []migration) error {
	seed, err := classifySeedFootprint(ctx, conn)
	if err != nil {
		return err
	}
	if seed == seedAmbiguous {
		return fmt.Errorf("refusing untracked schema with partial or ambiguous %s data", legacyPrincipalSeed)
	}
	if !hasMigration(migrations, baseSchemaMigration) || !hasMigration(migrations, legacyPrincipalSeed) {
		return fmt.Errorf("cannot adopt schema without the repository's 001 and 002 migration definitions")
	}
	return createMigrationHistory(ctx, conn, []ledgerEntry{
		{version: baseSchemaMigration, disposition: dispositionAdopted},
		{version: legacyPrincipalSeed, disposition: seedDisposition(seed)},
	})
}

func adoptIntoEmptyHistory(ctx context.Context, conn *pgxpool.Conn, migrations []migration) error {
	seed, err := classifySeedFootprint(ctx, conn)
	if err != nil {
		return err
	}
	if seed == seedAmbiguous {
		return fmt.Errorf("refusing empty ledger with partial or ambiguous %s data", legacyPrincipalSeed)
	}
	if !hasMigration(migrations, baseSchemaMigration) || !hasMigration(migrations, legacyPrincipalSeed) {
		return fmt.Errorf("cannot adopt schema without the repository's 001 and 002 migration definitions")
	}
	return insertAdoptedHistory(ctx, conn.Conn(), seed)
}

func resolveLegacyDisposition(ctx context.Context, conn *pgxpool.Conn, current state, migrations []migration) (state, error) {
	if !current.applied[baseSchemaMigration] {
		return state{}, fmt.Errorf("cannot resolve %s disposition before %s is applied", legacyPrincipalSeed, baseSchemaMigration)
	}
	if !hasMigration(migrations, legacyPrincipalSeed) {
		return state{}, fmt.Errorf("migration %s is absent from the repository", legacyPrincipalSeed)
	}
	seed, err := classifySeedFootprint(ctx, conn)
	if err != nil {
		return state{}, err
	}
	if seed == seedAmbiguous {
		return state{}, fmt.Errorf("refusing unresolved or partial %s footprint", legacyPrincipalSeed)
	}
	if err := recordDisposition(ctx, conn, legacyPrincipalSeed, seedDisposition(seed)); err != nil {
		return state{}, err
	}
	return inspectWith(ctx, conn)
}

type ledgerEntry struct {
	version     string
	disposition migrationDisposition
}

func createMigrationHistory(ctx context.Context, conn *pgxpool.Conn, entries []ledgerEntry) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `CREATE TABLE public.rbac_schema_migrations (
		version text PRIMARY KEY,
		disposition text NOT NULL CHECK (disposition IN ('applied','adopted-applied','adopted-manager-era','excluded')),
		applied_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		return fmt.Errorf("create migration ledger: %w", err)
	}
	for _, entry := range entries {
		if _, err := tx.Exec(ctx, `INSERT INTO public.rbac_schema_migrations(version, disposition) VALUES ($1, $2)`, entry.version, entry.disposition); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func insertAdoptedHistory(ctx context.Context, conn *pgx.Conn, seed seedState) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `INSERT INTO public.rbac_schema_migrations(version, disposition) VALUES ($1, $2)`, baseSchemaMigration, dispositionAdopted); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.rbac_schema_migrations(version, disposition) VALUES ($1, $2)`, legacyPrincipalSeed, seedDisposition(seed)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func recordDisposition(ctx context.Context, conn *pgxpool.Conn, version string, disposition migrationDisposition) error {
	_, err := conn.Exec(ctx, `INSERT INTO public.rbac_schema_migrations(version, disposition) VALUES ($1, $2) ON CONFLICT (version) DO NOTHING`, version, disposition)
	return err
}

func migrationRecordSQL(version string, disposition migrationDisposition) string {
	return "INSERT INTO public." + migrationTable + " (version, disposition) VALUES (" + quote(version) + ", " + quote(string(disposition)) + ") " +
		"ON CONFLICT (version) DO UPDATE SET disposition = excluded.disposition, applied_at = now()"
}

func seedDisposition(seed seedState) migrationDisposition {
	switch seed {
	case seedAbsent:
		return dispositionExcluded
	case seedManager:
		return dispositionAdoptedManager
	default:
		return dispositionAdopted
	}
}

func validDisposition(disposition migrationDisposition) bool {
	switch disposition {
	case dispositionApplied, dispositionAdopted, dispositionAdoptedManager, dispositionExcluded:
		return true
	default:
		return false
	}
}

func requireSupportedMigrationVersions(current state, migrations []migration) error {
	known := make(map[string]bool, len(migrations))
	for _, item := range migrations {
		known[item.version] = true
	}
	for version := range current.dispositions {
		if !known[version] {
			return fmt.Errorf("migration ledger contains unsupported historical version %q", version)
		}
	}
	return nil
}
