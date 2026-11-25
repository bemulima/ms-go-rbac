package main

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestMCPProfileUsesExactMigrationSequence(t *testing.T) {
	migrations, err := discoverMigrations("../../migrations")
	if err != nil {
		t.Fatal(err)
	}
	selected, err := mcpProfileMigrations(migrations)
	if err != nil {
		t.Fatal(err)
	}
	const signup = "003_signup_provisioning_receipts.up.sql"
	const operator = "004_operator_bootstrap_receipts.up.sql"
	want := []string{baseSchemaMigration, legacyPrincipalSeed, signup, operator}
	if got := migrationVersions(selected); !slices.Equal(got, want) {
		t.Fatalf("MCP inventory = %v; want %v", got, want)
	}
	toApply, err := migrationsForProfile(migrations, profileMCP)
	if err != nil {
		t.Fatal(err)
	}
	want = []string{baseSchemaMigration, signup, operator}
	if got := migrationVersions(toApply); !slices.Equal(got, want) {
		t.Fatalf("MCP forward migrations = %v; want %v", got, want)
	}
	if _, err := mcpProfileMigrations(selected[:len(selected)-1]); err == nil {
		t.Fatal("MCP profile accepted an incomplete source inventory")
	}
	general, err := migrationsForProfile(migrations, profileSchema)
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, "005_cat49_disposable_reviewer_grant.up.sql", "005_mentor_role_owner.up.sql", "006_mcp_mentor_profile_permission.up.sql", "007_mcp_mentor_offers_permission.up.sql", "008_mcp_mentor_workspace_read_permissions.up.sql", "009_mcp_mentor_skill_draft_permission.up.sql")
	if got := migrationVersions(general); !slices.Equal(got, want) {
		t.Fatalf("general schema forward migrations = %v; want %v", got, want)
	}
}

func TestMCPProfileRefusesFixedLegacyAssignmentsBeforeContinuing(t *testing.T) {
	current := state{
		historyExists:   true,
		historyHasState: true,
		applied:         map[string]bool{baseSchemaMigration: true},
		dispositions:    map[string]migrationDisposition{baseSchemaMigration: dispositionApplied},
	}
	ctx := context.Background()
	if err := validateMCPMigrationState(ctx, mcpLegacyAssignmentProbe{t: t}, current); err != nil {
		t.Fatalf("a failed 001-only attempt without fixed legacy grants can continue: %v", err)
	}
	if err := validateMCPMigrationState(ctx, mcpLegacyAssignmentProbe{t: t, exists: true}, current); err == nil {
		t.Fatal("MCP profile accepted fixed legacy assignments with an incomplete ledger")
	}
	readErr := errors.New("read failed")
	if err := validateMCPMigrationState(ctx, mcpLegacyAssignmentProbe{t: t, err: readErr}, current); !errors.Is(err, readErr) {
		t.Fatalf("MCP profile did not fail closed on the assignment read: %v", err)
	}
}

type mcpLegacyAssignmentProbe struct {
	catalogReader
	t      *testing.T
	exists bool
	err    error
}

func (probe mcpLegacyAssignmentProbe) QueryRow(_ context.Context, _ string, args ...any) pgx.Row {
	probe.t.Helper()
	if len(args) != 1 || !slices.Equal(args[0].([]string), legacySeedPrincipalIDs()) {
		probe.t.Fatal("MCP profile did not read the exact fixed legacy principals")
	}
	return probe
}

func (probe mcpLegacyAssignmentProbe) Scan(dest ...any) error {
	if probe.err != nil {
		return probe.err
	}
	*dest[0].(*bool) = probe.exists
	return nil
}

func TestMCPProfileAcceptsOnlyFreshOrExactLedgerPrefix(t *testing.T) {
	if err := validateMCPMigrationHistory(state{}); err != nil {
		t.Fatalf("fresh database rejected: %v", err)
	}
	known := state{historyExists: true, historyHasState: true, dispositions: map[string]migrationDisposition{}}
	for _, version := range []string{baseSchemaMigration, legacyPrincipalSeed, "003_signup_provisioning_receipts.up.sql", "004_operator_bootstrap_receipts.up.sql"} {
		known.dispositions[version] = dispositionApplied
		if version == legacyPrincipalSeed {
			known.dispositions[version] = dispositionExcluded
		}
		if err := validateMCPMigrationHistory(known); err != nil {
			t.Fatalf("exact ledger prefix ending at %s rejected: %v", version, err)
		}
	}
	for name, ledger := range map[string]state{
		"untracked":     {tableCount: 1},
		"legacy ledger": {historyExists: true},
		"legacy seed": {historyExists: true, historyHasState: true, dispositions: map[string]migrationDisposition{
			baseSchemaMigration: dispositionApplied, legacyPrincipalSeed: dispositionApplied,
		}},
		"adopted schema": {historyExists: true, historyHasState: true, dispositions: map[string]migrationDisposition{
			baseSchemaMigration: dispositionAdopted,
		}},
		"gap": {historyExists: true, historyHasState: true, dispositions: map[string]migrationDisposition{
			baseSchemaMigration: dispositionApplied, "003_signup_provisioning_receipts.up.sql": dispositionApplied,
		}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateMCPMigrationHistory(ledger); err == nil {
				t.Fatal("out-of-profile migration history accepted")
			}
		})
	}
	for _, other := range []string{"005_cat49_disposable_reviewer_grant.up.sql", "005_mentor_role_owner.up.sql"} {
		known.dispositions[other] = dispositionApplied
		if err := validateMCPMigrationHistory(known); err == nil {
			t.Fatalf("out-of-profile migration history accepted: %s", other)
		}
		delete(known.dispositions, other)
	}
}
