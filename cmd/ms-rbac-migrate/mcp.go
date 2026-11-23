package main

import (
	"context"
	"errors"
	"fmt"
)

// Keep the exact MCP disposable profile separate from the general schema,
// which also includes the CAT-49 Reviewer and MENT-27 Mentor schemas.
var mcpMigrationOrder = [...]string{
	baseSchemaMigration,
	legacyPrincipalSeed,
	"003_signup_provisioning_receipts.up.sql",
	"004_operator_bootstrap_receipts.up.sql",
}

func validateMCPMigrationState(ctx context.Context, q catalogReader, current state) error {
	if err := validateMCPMigrationHistory(current); err != nil {
		return err
	}
	if !current.applied[baseSchemaMigration] {
		return nil
	}
	// A failure after 001 can precede the 002 ledger marker. Never
	// adopt fixed legacy principal grants on the MCP profile.
	var exists bool
	err := q.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM public.principal_role WHERE principal_id::text = ANY($1::text[])
	)`, legacySeedPrincipalIDs()).Scan(&exists)
	if err != nil {
		return fmt.Errorf("inspect legacy principal assignments: %w", err)
	}
	if exists {
		return errors.New("MCP profile requires all fixed legacy principal grants to be absent")
	}
	return nil
}

func mcpProfileMigrations(migrations []migration) ([]migration, error) {
	byVersion := make(map[string]migration, len(migrations))
	for _, item := range migrations {
		byVersion[item.version] = item
	}
	selected := make([]migration, 0, len(mcpMigrationOrder))
	for _, version := range mcpMigrationOrder {
		item, ok := byVersion[version]
		if !ok {
			return nil, fmt.Errorf("MCP profile requires %s", version)
		}
		selected = append(selected, item)
	}
	return selected, nil
}

func validateMCPMigrationHistory(current state) error {
	if current.historyExists && !current.historyHasState {
		return errors.New("MCP profile refuses a legacy migration ledger without dispositions")
	}
	if len(current.dispositions) == 0 && current.tableCount != 0 {
		return errors.New("MCP profile refuses to adopt an untracked database with public tables")
	}
	remaining := len(current.dispositions)
	foundGap := false
	for _, version := range mcpMigrationOrder {
		disposition, ok := current.dispositions[version]
		if !ok {
			foundGap = true
			continue
		}
		expected := dispositionApplied
		if version == legacyPrincipalSeed {
			expected = dispositionExcluded
		}
		if foundGap || disposition != expected {
			return fmt.Errorf("MCP profile refuses %s with disposition %q or a missing predecessor", version, disposition)
		}
		remaining--
	}
	if remaining != 0 {
		return errors.New("MCP profile refuses migration ledger entries outside its exact sequence")
	}
	return nil
}
