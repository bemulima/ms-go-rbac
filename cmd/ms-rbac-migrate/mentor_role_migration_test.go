package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// These are source-contract checks, not PostgreSQL execution or SQL acceptance.
func TestMentorRoleMigrationDiscoveryAndHistory(t *testing.T) {
	dir := filepath.Join("..", "..", "migrations")
	items, err := discoverMigrations(dir)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range items {
		if item.version == "005_mentor_role_owner.up.sql" {
			found = item.downPath == filepath.Join(dir, "005_mentor_role_owner.down.sql")
		}
	}
	if !found {
		t.Fatal("Mentor migration and guarded rollback must be discovered together")
	}
	historical := map[string]string{
		"001_init.sql": "7ad562fd6f1ca1d220b2937c495b5d096ee3287218d1ca6868a957004848d89a",
		"002_seed_default_roles_and_principals.up.sql":   "fc7ab4fbb48357258e7f2f0621b5820d88ea65925996c0f9644f7da71ebf4799",
		"002_seed_default_roles_and_principals.down.sql": "a8d93b9fe20cd344c970a1e16f5f64b9b602153f1b6a809fae45ca5e0adbeaf8",
		"003_signup_provisioning_receipts.up.sql":        "676577972535ba55ea0f0f2f388fe186537c94396f47c672ea36281b13cbd026",
		"003_signup_provisioning_receipts.down.sql":      "dec34ffae350e52a601066160ed7f55bdce1472410a36b746f0675b517bb87a9",
		"004_operator_bootstrap_receipts.up.sql":         "d04cf9c11b7cd8341de8aa80e116b608655e2756b333cf193ee0469d8f775ed8",
		"004_operator_bootstrap_receipts.down.sql":       "71d03007155746f78b814da61c0f62330336826f671f7ea8c5142b3a1c679f11",
	}
	for name, expected := range historical {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(b)); got != expected {
			t.Errorf("historical migration %s changed", name)
		}
	}
}

func TestMentorRoleMigrationOwnedMetadataAndNoGrants(t *testing.T) {
	up := mentorMigrationText(t, "up")
	for _, required := range []string{
		"create table public.mentor_role_scope",
		"singleton boolean primary key check (singleton)",
		"unique (role_id, service_id)",
		"refusing adoption of existing mentor metadata",
		"insert into public.role (key, title) values ('mentor', 'mentor') returning id",
		"insert into public.service (key, title) values ('ms-go-mentor', 'mentor service') returning id",
		"insert into public.mentor_role_scope",
		"before update or delete or truncate on public.mentor_role_scope",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("missing metadata invariant: %s", required)
		}
	}
	for _, forbidden := range []string{"insert into public.principal_role", "update public.principal_role", "delete from public.principal_role", "insert into public.role_permission", "insert into public.role_hierarchy", "on conflict", "grant "} {
		if strings.Contains(up, forbidden) {
			t.Errorf("migration must not grant, adopt or repair authority: %s", forbidden)
		}
	}
}

func TestMentorRoleMigrationPinsCatalogSearchPath(t *testing.T) {
	for _, direction := range []string{"up", "down"} {
		t.Run(direction, func(t *testing.T) {
			sql := mentorMigrationText(t, direction)
			pin := strings.Index(sql, "set local search_path = pg_catalog, public, pg_temp")
			lock := strings.Index(sql, "lock table")
			if pin < 0 || lock < 0 || pin > lock {
				t.Fatal("schema/catalog reads must pin pg_temp last before any lock or DDL")
			}
		})
	}
}

func TestMentorRoleMigrationImmutableReceiptAndTerminalFence(t *testing.T) {
	up := mentorMigrationText(t, "up")
	for _, required := range []string{
		"create table public.mentor_role_command_receipt",
		"primary key (issuer, request_id)",
		"unique (application_id, application_revision)",
		"check (issuer = 'ms-go-auth')",
		"check (role_key = 'mentor')",
		"check (service_key = 'ms-go-mentor')",
		"decision = 'approve' and application_revision = 2",
		"decision = 'suspend' and application_revision in (3, 4)",
		"foreign key (role_id, service_id) references public.mentor_role_scope (role_id, service_id)",
		"before update or delete or truncate on public.mentor_role_command_receipt",
		"create table public.mentor_role_fence",
		"application_id uuid primary key",
		"unique (target_user_id, role_key, service_key)",
		"references public.mentor_role_command_receipt",
		"old.application_revision <> 2",
		"new.application_revision not in (3, 4)",
		"mentor role fence binding is immutable",
		"mentor role fence is terminal",
		"before truncate on public.mentor_role_fence",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("missing receipt/fence invariant: %s", required)
		}
	}
}

func TestMentorRoleMigrationGuardedRollback(t *testing.T) {
	down := mentorMigrationText(t, "down")
	for _, required := range []string{
		"lock table public.role, public.service, public.service_role in share row exclusive mode",
		"refusing rollback of nonempty mentor role history",
		"from public.mentor_role_command_receipt",
		"from public.mentor_role_fence",
		"from public.mentor_role_scope",
		"refusing rollback of drifted mentor metadata",
		"refusing rollback of referenced mentor metadata",
		"from public.principal_role",
		"from public.role_hierarchy",
		"from public.role_permission",
		"from public.service_permission",
		"from public.principal_override",
		"refusing rollback with unknown metadata references",
		"where id = owned_role_id",
		"where id = owned_service_id",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("missing rollback guard: %s", required)
		}
	}
	if strings.Contains(down, "cascade") || strings.Contains(down, "truncate ") {
		t.Fatal("rollback must not cascade or truncate durable history")
	}
	guard := strings.Index(down, "refusing rollback of referenced mentor metadata")
	drop := strings.Index(down, "drop table public.mentor_role_fence")
	if guard < 0 || drop <= guard {
		t.Fatal("rollback must finish all data/ownership guards before removing owner tables")
	}
}

func TestMentorRoleMigrationRollbackPinsReferenceColumns(t *testing.T) {
	down := mentorMigrationText(t, "down")
	// A new secondary FK in an existing table must not inherit an allowlist
	// exemption just because its table is already known.
	for _, pin := range []string{
		"c.conkey = array[source_att.attnum]",
		"c.confkey = array[target_att.attnum]",
		"not source_att.attisdropped",
		"not target_att.attisdropped",
	} {
		if !strings.Contains(down, pin) {
			t.Errorf("unknown-reference guard must pin exact columns: %s", pin)
		}
	}
	re := regexp.MustCompile(`\('public\.([a-z_]+)'::regclass, '([a-z_]+)', 'public\.([a-z_]+)'::regclass, 'id'\)`)
	var actual []string
	for _, match := range re.FindAllStringSubmatch(down, -1) {
		actual = append(actual, match[1]+"."+match[2]+"->"+match[3]+".id")
	}
	expected := []string{
		"role_hierarchy.role_id->role.id", "role_hierarchy.parent_role_id->role.id",
		"role_permission.role_id->role.id",
		"service_role.role_id->role.id", "service_role.service_id->service.id",
		"service_permission.service_id->service.id",
		"principal_role.role_id->role.id", "principal_role.service_id->service.id",
		"principal_override.service_id->service.id",
		"mentor_role_scope.role_id->role.id", "mentor_role_scope.service_id->service.id",
	}
	sort.Strings(actual)
	sort.Strings(expected)
	if strings.Join(actual, "\n") != strings.Join(expected, "\n") {
		t.Fatalf("rollback reference allowlist must contain only the eleven exact known mappings; got %v", actual)
	}
}

func mentorMigrationText(t *testing.T, direction string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "migrations", "005_mentor_role_owner."+direction+".sql"))
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, line := range strings.Split(string(b), "\n") {
		if before, _, ok := strings.Cut(line, "--"); ok {
			line = before
		}
		lines = append(lines, line)
	}
	return strings.ToLower(strings.Join(strings.Fields(strings.Join(lines, "\n")), " "))
}
