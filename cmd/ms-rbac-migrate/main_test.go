package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverMigrationsUsesForwardFilesInLexicalOrder(t *testing.T) {
	directory := t.TempDir()
	for _, name := range []string{"002_seed.up.sql", "002_seed.down.sql", "001_init.sql", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("-- test"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	migrations, err := discoverMigrations(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(migrations) != 2 || migrations[0].version != "001_init.sql" || migrations[1].version != "002_seed.up.sql" {
		t.Fatalf("unexpected migrations: %#v", migrations)
	}
	if migrations[1].downPath != filepath.Join(directory, "002_seed.down.sql") {
		t.Fatalf("unexpected down path: %q", migrations[1].downPath)
	}
}

func TestSchemaProfileExcludesOnlyTheLegacyPrincipalSeed(t *testing.T) {
	migrations := []migration{
		{version: "001_init.sql"},
		{version: legacyPrincipalSeed},
		{version: "003_future_schema.sql"},
		{version: "004_another_schema.sql"},
	}

	selected, err := migrationsForProfile(migrations, profileSchema)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"001_init.sql", "003_future_schema.sql", "004_another_schema.sql"}
	if len(selected) != len(want) {
		t.Fatalf("schema profile selected %v, want %v", migrationVersions(selected), want)
	}
	for index, version := range want {
		if selected[index].version != version {
			t.Fatalf("schema profile selected %v, want %v", migrationVersions(selected), want)
		}
	}
}

func TestLegacyProfileRetainsTheCompleteMigrationSequence(t *testing.T) {
	migrations := []migration{{version: "001_init.sql"}, {version: legacyPrincipalSeed}, {version: "003_future_schema.sql"}}
	selected, err := migrationsForProfile(migrations, profileLegacy)
	if err != nil {
		t.Fatal(err)
	}
	if got := migrationVersions(selected); len(got) != 3 || got[1] != legacyPrincipalSeed {
		t.Fatalf("legacy profile selected %v, want all migrations including %s", got, legacyPrincipalSeed)
	}
}

func migrationVersions(migrations []migration) []string {
	versions := make([]string, len(migrations))
	for index, item := range migrations {
		versions[index] = item.version
	}
	return versions
}
