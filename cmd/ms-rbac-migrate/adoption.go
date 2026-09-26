package main

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/example/ms-rbac-service/internal/domain/model"
	"github.com/jackc/pgx/v5"
)

type catalogReader interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

type schemaClass string

const (
	schemaFresh       schemaClass = "fresh"
	schemaHistorical  schemaClass = "historical-001"
	schemaUnsupported schemaClass = "unsupported"
)

type seedState string

const (
	seedAbsent       seedState = "absent"
	seedCurrent      seedState = "moderator-era"
	seedManager      seedState = "manager-era"
	seedAmbiguous    seedState = "ambiguous"
	legacyManagerKey           = "manager"
)

type seedRole struct {
	key   string
	title string
}

type seedGrant struct {
	principal string
	role      string
}

var currentSeedRoles = []seedRole{
	{key: "admin", title: "Admin"},
	{key: "moderator", title: "Moderator"},
	{key: "teacher", title: "Teacher"},
	{key: "student", title: "Student"},
	{key: "user", title: "User"},
	{key: "guest", title: "Guest"},
}

var managerSeedRoles = []seedRole{
	{key: "admin", title: "Admin"},
	{key: legacyManagerKey, title: "Manager"},
	{key: "teacher", title: "Teacher"},
	{key: "student", title: "Student"},
	{key: "user", title: "User"},
	{key: "guest", title: "Guest"},
}

var currentSeedGrants = []seedGrant{
	{principal: "00000000-0000-0000-0000-0000000000a1", role: "admin"},
	{principal: "00000000-0000-0000-0000-0000000000a2", role: "moderator"},
	{principal: "00000000-0000-0000-0000-0000000000a3", role: "teacher"},
	{principal: "00000000-0000-0000-0000-0000000000b1", role: "student"},
	{principal: "00000000-0000-0000-0000-0000000000b2", role: "student"},
	{principal: "00000000-0000-0000-0000-0000000000b3", role: "student"},
	{principal: "00000000-0000-0000-0000-0000000000c1", role: "user"},
}

var managerSeedGrants = []seedGrant{
	{principal: "00000000-0000-0000-0000-0000000000a1", role: "admin"},
	{principal: "00000000-0000-0000-0000-0000000000a2", role: legacyManagerKey},
	{principal: "00000000-0000-0000-0000-0000000000a3", role: "teacher"},
	{principal: "00000000-0000-0000-0000-0000000000b1", role: "student"},
	{principal: "00000000-0000-0000-0000-0000000000b2", role: "student"},
	{principal: "00000000-0000-0000-0000-0000000000b3", role: "student"},
	{principal: "00000000-0000-0000-0000-0000000000c1", role: "user"},
}

type expectedColumn struct {
	name     string
	typeName string
	notNull  bool
	defaultV string
}

var migration001Tables = map[string][]expectedColumn{
	"service": {
		{name: "id", typeName: "uuid", notNull: true, defaultV: "gen_random_uuid()"},
		{name: "key", typeName: "text", notNull: true},
		{name: "title", typeName: "text", notNull: true},
	},
	"role": {
		{name: "id", typeName: "uuid", notNull: true, defaultV: "gen_random_uuid()"},
		{name: "key", typeName: "text", notNull: true},
		{name: "title", typeName: "text", notNull: true},
	},
	"role_hierarchy": {
		{name: "role_id", typeName: "uuid", notNull: true},
		{name: "parent_role_id", typeName: "uuid", notNull: true},
	},
	"permission": {
		{name: "id", typeName: "uuid", notNull: true, defaultV: "gen_random_uuid()"},
		{name: "action", typeName: "text", notNull: true},
		{name: "resource_kind", typeName: "text", notNull: true},
	},
	"role_permission": {
		{name: "role_id", typeName: "uuid", notNull: true},
		{name: "permission_id", typeName: "uuid", notNull: true},
		{name: "resource_id", typeName: "uuid", notNull: true},
	},
	"service_role": {
		{name: "role_id", typeName: "uuid", notNull: true},
		{name: "service_id", typeName: "uuid", notNull: true},
	},
	"service_permission": {
		{name: "permission_id", typeName: "uuid", notNull: true},
		{name: "service_id", typeName: "uuid", notNull: true},
	},
	"principal_role": {
		{name: "principal_id", typeName: "uuid", notNull: true},
		{name: "principal_kind", typeName: "principal_kind", notNull: true},
		{name: "role_id", typeName: "uuid", notNull: true},
		{name: "tenant_id", typeName: "uuid", notNull: true},
		{name: "service_id", typeName: "uuid", notNull: true},
		{name: "resource_kind", typeName: "text", notNull: true},
		{name: "resource_id", typeName: "uuid", notNull: true},
	},
	"principal_override": {
		{name: "principal_id", typeName: "uuid", notNull: true},
		{name: "principal_kind", typeName: "principal_kind", notNull: true},
		{name: "permission_id", typeName: "uuid", notNull: true},
		{name: "effect", typeName: "override_effect", notNull: true},
		{name: "tenant_id", typeName: "uuid", notNull: true},
		{name: "service_id", typeName: "uuid", notNull: true},
		{name: "resource_kind", typeName: "text", notNull: true},
		{name: "resource_id", typeName: "uuid", notNull: true},
	},
	"superadmin_principal": {
		{name: "principal_id", typeName: "uuid", notNull: true},
		{name: "principal_kind", typeName: "principal_kind", notNull: true},
	},
}

var migration001Indexes = []string{
	"permission|action,resource_kind|true|false",
	"permission|id|true|true",
	"principal_override|principal_id,principal_kind,permission_id,tenant_id,service_id,resource_kind,resource_id|true|true",
	"principal_override|principal_id,principal_kind,tenant_id,service_id,resource_kind,resource_id|false|false",
	"principal_role|principal_id,principal_kind,role_id,tenant_id,service_id,resource_kind,resource_id|true|true",
	"principal_role|principal_id,principal_kind,tenant_id,service_id,resource_kind,resource_id|false|false",
	"role|id|true|true",
	"role|key|true|false",
	"role_hierarchy|role_id,parent_role_id|true|true",
	"role_permission|role_id,permission_id,resource_id|true|true",
	"service|id|true|true",
	"service|key|true|false",
	"service_permission|permission_id,service_id|true|true",
	"service_role|role_id,service_id|true|true",
	"superadmin_principal|principal_id|true|true",
}

var migration001Constraints = []string{
	"permission|primarykey(id)",
	"permission|unique(action,resource_kind)",
	"principal_override|primarykey(principal_id,principal_kind,permission_id,tenant_id,service_id,resource_kind,resource_id)",
	"principal_override|foreignkey(permission_id)referencespermission(id)ondeletecascade",
	"principal_override|foreignkey(service_id)referencesservice(id)ondeletecascade",
	"principal_role|primarykey(principal_id,principal_kind,role_id,tenant_id,service_id,resource_kind,resource_id)",
	"principal_role|foreignkey(role_id)referencesrole(id)ondeletecascade",
	"principal_role|foreignkey(service_id)referencesservice(id)ondeletecascade",
	"role|primarykey(id)",
	"role|unique(key)",
	"role_hierarchy|primarykey(role_id,parent_role_id)",
	"role_hierarchy|foreignkey(role_id)referencesrole(id)ondeletecascade",
	"role_hierarchy|foreignkey(parent_role_id)referencesrole(id)ondeletecascade",
	"role_hierarchy|check(role_id<>parent_role_id)",
	"role_permission|primarykey(role_id,permission_id,resource_id)",
	"role_permission|foreignkey(role_id)referencesrole(id)ondeletecascade",
	"role_permission|foreignkey(permission_id)referencespermission(id)ondeletecascade",
	"service|primarykey(id)",
	"service|unique(key)",
	"service_permission|primarykey(permission_id,service_id)",
	"service_permission|foreignkey(permission_id)referencespermission(id)ondeletecascade",
	"service_permission|foreignkey(service_id)referencesservice(id)ondeletecascade",
	"service_role|primarykey(role_id,service_id)",
	"service_role|foreignkey(role_id)referencesrole(id)ondeletecascade",
	"service_role|foreignkey(service_id)referencesservice(id)ondeletecascade",
	"superadmin_principal|primarykey(principal_id)",
}

func classifyApplicationSchema(ctx context.Context, q catalogReader) (schemaClass, error) {
	if err := verifyNoPublicRewriteRules(ctx, q); err != nil {
		return schemaUnsupported, err
	}

	var relationCount, routineCount, otherTypeCount, otherObjectCount int
	if err := q.QueryRow(ctx, `
		SELECT count(*)
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public'
		  AND c.relkind IN ('r','p','v','m','S','f','i','I')
		  AND c.relname <> $1
		  AND NOT EXISTS (
			SELECT 1 FROM pg_index migration_index
			JOIN pg_class migration_table_class ON migration_table_class.oid = migration_index.indrelid
			JOIN pg_namespace migration_table_namespace ON migration_table_namespace.oid = migration_table_class.relnamespace
			WHERE migration_index.indexrelid = c.oid
			  AND migration_table_namespace.nspname = 'public'
			  AND migration_table_class.relname = $1
		  )
		  AND NOT EXISTS (
			SELECT 1 FROM pg_depend d
			JOIN pg_extension e ON e.oid = d.refobjid
			WHERE d.refclassid = 'pg_extension'::regclass
			  AND d.classid = 'pg_class'::regclass
			  AND d.objid = c.oid
			  AND d.deptype = 'e'
			  AND e.extname = 'pgcrypto'
		  )`, migrationTable).Scan(&relationCount); err != nil {
		return schemaUnsupported, err
	}
	if err := q.QueryRow(ctx, `
		SELECT count(*)
		FROM pg_proc p
		JOIN pg_namespace n ON n.oid = p.pronamespace
		WHERE n.nspname = 'public'
		  AND NOT EXISTS (
			SELECT 1 FROM pg_depend d
			JOIN pg_extension e ON e.oid = d.refobjid
			WHERE d.refclassid = 'pg_extension'::regclass
			  AND d.classid = 'pg_proc'::regclass
			  AND d.objid = p.oid
			  AND d.deptype = 'e'
			  AND e.extname = 'pgcrypto'
		  )`).Scan(&routineCount); err != nil {
		return schemaUnsupported, err
	}
	if err := q.QueryRow(ctx, `
		SELECT count(*)
		FROM pg_type t
		JOIN pg_namespace n ON n.oid = t.typnamespace
		LEFT JOIN pg_class c ON c.reltype = t.oid
		WHERE n.nspname = 'public'
		  AND (t.typtype IN ('e','d','r','p') OR (t.typtype = 'c' AND c.oid IS NULL) OR (t.typtype = 'b' AND t.typelem = 0 AND t.typrelid = 0))
		  AND NOT EXISTS (
			SELECT 1 FROM pg_depend d
			JOIN pg_extension e ON e.oid = d.refobjid
			WHERE d.refclassid = 'pg_extension'::regclass
			  AND d.classid = 'pg_type'::regclass
			  AND d.objid = t.oid
			  AND d.deptype = 'e'
			  AND e.extname = 'pgcrypto'
		  )`).Scan(&otherTypeCount); err != nil {
		return schemaUnsupported, err
	}
	if err := q.QueryRow(ctx, `
		SELECT count(*) FROM (
			SELECT o.oid FROM pg_operator o JOIN pg_namespace n ON n.oid = o.oprnamespace
			WHERE n.nspname = 'public' AND NOT EXISTS (
				SELECT 1 FROM pg_depend d JOIN pg_extension e ON e.oid = d.refobjid
				WHERE d.refclassid = 'pg_extension'::regclass AND d.classid = 'pg_operator'::regclass
				  AND d.objid = o.oid AND d.deptype = 'e' AND e.extname = 'pgcrypto'
			)
			UNION ALL
			SELECT o.oid FROM pg_opclass o JOIN pg_namespace n ON n.oid = o.opcnamespace
			WHERE n.nspname = 'public' AND NOT EXISTS (
				SELECT 1 FROM pg_depend d JOIN pg_extension e ON e.oid = d.refobjid
				WHERE d.refclassid = 'pg_extension'::regclass AND d.classid = 'pg_opclass'::regclass
				  AND d.objid = o.oid AND d.deptype = 'e' AND e.extname = 'pgcrypto'
			)
			UNION ALL
			SELECT o.oid FROM pg_opfamily o JOIN pg_namespace n ON n.oid = o.opfnamespace
			WHERE n.nspname = 'public' AND NOT EXISTS (
				SELECT 1 FROM pg_depend d JOIN pg_extension e ON e.oid = d.refobjid
				WHERE d.refclassid = 'pg_extension'::regclass AND d.classid = 'pg_opfamily'::regclass
				  AND d.objid = o.oid AND d.deptype = 'e' AND e.extname = 'pgcrypto'
			)
			UNION ALL
			SELECT o.oid FROM pg_collation o JOIN pg_namespace n ON n.oid = o.collnamespace
			WHERE n.nspname = 'public' AND NOT EXISTS (
				SELECT 1 FROM pg_depend d JOIN pg_extension e ON e.oid = d.refobjid
				WHERE d.refclassid = 'pg_extension'::regclass AND d.classid = 'pg_collation'::regclass
				  AND d.objid = o.oid AND d.deptype = 'e' AND e.extname = 'pgcrypto'
			)
			UNION ALL
			SELECT o.oid FROM pg_conversion o JOIN pg_namespace n ON n.oid = o.connamespace
			WHERE n.nspname = 'public' AND NOT EXISTS (
				SELECT 1 FROM pg_depend d JOIN pg_extension e ON e.oid = d.refobjid
				WHERE d.refclassid = 'pg_extension'::regclass AND d.classid = 'pg_conversion'::regclass
				  AND d.objid = o.oid AND d.deptype = 'e' AND e.extname = 'pgcrypto'
			)
			UNION ALL
			SELECT o.oid FROM pg_ts_config o JOIN pg_namespace n ON n.oid = o.cfgnamespace WHERE n.nspname = 'public'
			UNION ALL
			SELECT o.oid FROM pg_ts_dict o JOIN pg_namespace n ON n.oid = o.dictnamespace WHERE n.nspname = 'public'
			UNION ALL
			SELECT o.oid FROM pg_ts_parser o JOIN pg_namespace n ON n.oid = o.prsnamespace WHERE n.nspname = 'public'
			UNION ALL
			SELECT o.oid FROM pg_ts_template o JOIN pg_namespace n ON n.oid = o.tmplnamespace WHERE n.nspname = 'public'
		) objects`).Scan(&otherObjectCount); err != nil {
		return schemaUnsupported, err
	}

	if relationCount == 0 && routineCount == 0 && otherTypeCount == 0 && otherObjectCount == 0 {
		return schemaFresh, nil
	}
	if err := verifyMigration001Catalog(ctx, q); err != nil {
		return schemaUnsupported, err
	}
	return schemaHistorical, nil
}

func verifyMigration001Catalog(ctx context.Context, q catalogReader) error {
	if err := verifyNoPublicRewriteRules(ctx, q); err != nil {
		return err
	}

	var actualTables []string
	rows, err := q.Query(ctx, `
		SELECT c.relname
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relkind IN ('r','p','v','m','S','f')
		  AND c.relname <> $1
		  AND NOT EXISTS (
			SELECT 1 FROM pg_depend d
			JOIN pg_extension e ON e.oid = d.refobjid
			WHERE d.refclassid = 'pg_extension'::regclass
			  AND d.classid = 'pg_class'::regclass
			  AND d.objid = c.oid AND d.deptype = 'e' AND e.extname = 'pgcrypto'
		  )
		ORDER BY c.relname`, migrationTable)
	if err != nil {
		return err
	}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		actualTables = append(actualTables, name)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	expectedTables := make([]string, 0, len(migration001Tables))
	for name := range migration001Tables {
		expectedTables = append(expectedTables, name)
	}
	sort.Strings(expectedTables)
	if !equalStrings(actualTables, expectedTables) {
		return fmt.Errorf("untracked schema tables do not exactly match migration 001: got %v, want %v", actualTables, expectedTables)
	}
	if err := verifyMigration001TableFlags(ctx, q); err != nil {
		return err
	}

	type actualColumn struct {
		table, name, typeName, defaultV string
		position                        int
		notNull                         bool
	}
	var actualColumns []actualColumn
	rows, err = q.Query(ctx, `
		SELECT c.relname, a.attname, pg_catalog.format_type(a.atttypid, a.atttypmod),
		       a.attnotnull, COALESCE(pg_get_expr(d.adbin, d.adrelid), ''), a.attnum
		FROM pg_attribute a
		JOIN pg_class c ON c.oid = a.attrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		LEFT JOIN pg_attrdef d ON d.adrelid = c.oid AND d.adnum = a.attnum
		WHERE n.nspname = 'public' AND c.relkind IN ('r','p')
		  AND c.relname <> $1 AND a.attnum > 0 AND NOT a.attisdropped
		ORDER BY c.relname, a.attnum`, migrationTable)
	if err != nil {
		return err
	}
	for rows.Next() {
		var column actualColumn
		if err := rows.Scan(&column.table, &column.name, &column.typeName, &column.notNull, &column.defaultV, &column.position); err != nil {
			rows.Close()
			return err
		}
		actualColumns = append(actualColumns, column)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	var expectedColumns []actualColumn
	for table, columns := range migration001Tables {
		for position, column := range columns {
			expectedColumns = append(expectedColumns, actualColumn{table: table, name: column.name, typeName: column.typeName, notNull: column.notNull, defaultV: column.defaultV, position: position + 1})
		}
	}
	sort.Slice(expectedColumns, func(i, j int) bool {
		if expectedColumns[i].table != expectedColumns[j].table {
			return expectedColumns[i].table < expectedColumns[j].table
		}
		return expectedColumns[i].position < expectedColumns[j].position
	})
	if len(actualColumns) != len(expectedColumns) {
		return fmt.Errorf("untracked schema column count is %d, want %d", len(actualColumns), len(expectedColumns))
	}
	for i := range expectedColumns {
		if actualColumns[i] != expectedColumns[i] {
			return fmt.Errorf("untracked schema column mismatch at %s.%s: got %+v, want %+v", expectedColumns[i].table, expectedColumns[i].name, actualColumns[i], expectedColumns[i])
		}
	}

	if err := verifyMigration001Constraints(ctx, q); err != nil {
		return err
	}
	if err := verifyMigration001Indexes(ctx, q); err != nil {
		return err
	}
	if err := verifyMigration001Enums(ctx, q); err != nil {
		return err
	}
	if err := verifyNoUnexpectedTypesOrRoutines(ctx, q); err != nil {
		return err
	}
	return nil
}

func verifyNoPublicRewriteRules(ctx context.Context, q catalogReader) error {
	var unexpected int
	if err := q.QueryRow(ctx, `
		SELECT count(*)
		FROM pg_rewrite r
		JOIN pg_class c ON c.oid = r.ev_class
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public'
		  AND NOT EXISTS (
			SELECT 1 FROM pg_depend d
			JOIN pg_extension e ON e.oid = d.refobjid
			WHERE d.refclassid = 'pg_extension'::regclass
			  AND d.classid = 'pg_rewrite'::regclass
			  AND d.objid = r.oid
			  AND d.deptype = 'e'
			  AND e.extname = 'pgcrypto'
		  )`).Scan(&unexpected); err != nil {
		return err
	}
	if unexpected != 0 {
		return fmt.Errorf("untracked public schema has %d rewrite rule(s)", unexpected)
	}
	return nil
}

func verifyMigration001Constraints(ctx context.Context, q catalogReader) error {
	rows, err := q.Query(ctx, `
		SELECT c.relname, pg_get_constraintdef(k.oid, true), k.convalidated, k.condeferrable, k.condeferred
		FROM pg_constraint k
		JOIN pg_class c ON c.oid = k.conrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relname <> $1
		ORDER BY c.relname, pg_get_constraintdef(k.oid, true)`, migrationTable)
	if err != nil {
		return err
	}
	var actual []string
	for rows.Next() {
		var table, definition string
		var validated, deferrable, deferred bool
		if err := rows.Scan(&table, &definition, &validated, &deferrable, &deferred); err != nil {
			rows.Close()
			return err
		}
		if !validated || deferrable || deferred {
			rows.Close()
			return fmt.Errorf("untracked schema constraint on %s has non-migration validation or deferral flags", table)
		}
		actual = append(actual, table+"|"+normalizeSQL(definition))
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	sort.Strings(actual)
	want := append([]string(nil), migration001Constraints...)
	sort.Strings(want)
	if !equalStrings(actual, want) {
		return fmt.Errorf("untracked schema constraints do not match migration 001: got %v, want %v", actual, want)
	}
	return nil
}

func verifyMigration001Indexes(ctx context.Context, q catalogReader) error {
	rows, err := q.Query(ctx, `
		SELECT table_class.relname,
		       string_agg(attribute.attname, ',' ORDER BY index_key.ordinality),
		       index_data.indisunique, index_data.indisprimary,
		       index_data.indisvalid, index_data.indisready, index_data.indislive,
		       index_data.indpred IS NULL, index_data.indexprs IS NULL,
		       index_data.indnkeyatts = index_data.indnatts
		FROM pg_index index_data
	JOIN pg_class index_class ON index_class.oid = index_data.indexrelid
		JOIN pg_class table_class ON table_class.oid = index_data.indrelid
		JOIN pg_namespace n ON n.oid = index_class.relnamespace
		CROSS JOIN LATERAL unnest(index_data.indkey::smallint[]) WITH ORDINALITY AS index_key(attnum, ordinality)
		JOIN pg_attribute attribute ON attribute.attrelid = table_class.oid AND attribute.attnum = index_key.attnum
		WHERE n.nspname = 'public' AND table_class.relname <> $1
		GROUP BY table_class.relname, index_data.indisunique, index_data.indisprimary, index_data.indexrelid
		ORDER BY table_class.relname`, migrationTable)
	if err != nil {
		return err
	}
	var actual []string
	for rows.Next() {
		var table, keys string
		var unique, primary, valid, ready, live, noPredicate, noExpressions, noIncludedColumns bool
		if err := rows.Scan(&table, &keys, &unique, &primary, &valid, &ready, &live, &noPredicate, &noExpressions, &noIncludedColumns); err != nil {
			rows.Close()
			return err
		}
		if !valid || !ready || !live || !noPredicate || !noExpressions || !noIncludedColumns {
			rows.Close()
			return fmt.Errorf("untracked schema index on %s has non-migration index flags", table)
		}
		actual = append(actual, fmt.Sprintf("%s|%s|%t|%t", table, keys, unique, primary))
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	sort.Strings(actual)
	want := append([]string(nil), migration001Indexes...)
	sort.Strings(want)
	if !equalStrings(actual, want) {
		return fmt.Errorf("untracked schema indexes do not match migration 001: got %v, want %v", actual, want)
	}
	return nil
}

func verifyMigration001Enums(ctx context.Context, q catalogReader) error {
	var pgcryptoPresent bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pgcrypto')`).Scan(&pgcryptoPresent); err != nil {
		return err
	}
	if !pgcryptoPresent {
		return fmt.Errorf("untracked schema is missing migration 001 extension pgcrypto")
	}
	rows, err := q.Query(ctx, `
		SELECT t.typname, string_agg(e.enumlabel, ',' ORDER BY e.enumsortorder)
		FROM pg_type t
		JOIN pg_namespace n ON n.oid = t.typnamespace
		JOIN pg_enum e ON e.enumtypid = t.oid
		WHERE n.nspname = 'public'
		GROUP BY t.typname ORDER BY t.typname`)
	if err != nil {
		return err
	}
	actual := make(map[string]string)
	for rows.Next() {
		var name, labels string
		if err := rows.Scan(&name, &labels); err != nil {
			rows.Close()
			return err
		}
		actual[name] = labels
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	want := map[string]string{"principal_kind": "user,service_account,group", "override_effect": "allow,deny"}
	if len(actual) != len(want) {
		return fmt.Errorf("untracked schema enums do not match migration 001: got %v, want %v", actual, want)
	}
	for name, labels := range want {
		if actual[name] != labels {
			return fmt.Errorf("untracked schema enum %q labels = %q, want %q", name, actual[name], labels)
		}
	}
	return nil
}

func verifyNoUnexpectedTypesOrRoutines(ctx context.Context, q catalogReader) error {
	var unexpectedTypes, unexpectedRoutines int
	if err := q.QueryRow(ctx, `
		SELECT count(*)
		FROM pg_type t
		JOIN pg_namespace n ON n.oid = t.typnamespace
		LEFT JOIN pg_class c ON c.reltype = t.oid
		WHERE n.nspname = 'public'
		  AND (t.typtype IN ('d','r','p') OR (t.typtype = 'c' AND c.oid IS NULL) OR (t.typtype = 'b' AND t.typelem = 0 AND t.typrelid = 0))
		  AND NOT EXISTS (
			SELECT 1 FROM pg_depend d
			JOIN pg_extension e ON e.oid = d.refobjid
			WHERE d.refclassid = 'pg_extension'::regclass
			  AND d.classid = 'pg_type'::regclass
			  AND d.objid = t.oid AND d.deptype = 'e' AND e.extname = 'pgcrypto'
		  )`).Scan(&unexpectedTypes); err != nil {
		return err
	}
	if err := q.QueryRow(ctx, `
		SELECT count(*)
		FROM pg_proc p
		JOIN pg_namespace n ON n.oid = p.pronamespace
		WHERE n.nspname = 'public'
		  AND NOT EXISTS (
			SELECT 1 FROM pg_depend d
			JOIN pg_extension e ON e.oid = d.refobjid
			WHERE d.refclassid = 'pg_extension'::regclass
			  AND d.classid = 'pg_proc'::regclass
			  AND d.objid = p.oid AND d.deptype = 'e' AND e.extname = 'pgcrypto'
		  )`).Scan(&unexpectedRoutines); err != nil {
		return err
	}
	var unexpectedObjects, unexpectedTriggers, unexpectedPolicies int
	if err := q.QueryRow(ctx, `
		SELECT count(*) FROM (
			SELECT o.oid FROM pg_operator o JOIN pg_namespace n ON n.oid = o.oprnamespace WHERE n.nspname = 'public'
			UNION ALL SELECT o.oid FROM pg_opclass o JOIN pg_namespace n ON n.oid = o.opcnamespace WHERE n.nspname = 'public'
			UNION ALL SELECT o.oid FROM pg_opfamily o JOIN pg_namespace n ON n.oid = o.opfnamespace WHERE n.nspname = 'public'
			UNION ALL SELECT o.oid FROM pg_collation o JOIN pg_namespace n ON n.oid = o.collnamespace WHERE n.nspname = 'public'
			UNION ALL SELECT o.oid FROM pg_conversion o JOIN pg_namespace n ON n.oid = o.connamespace WHERE n.nspname = 'public'
			UNION ALL SELECT o.oid FROM pg_ts_config o JOIN pg_namespace n ON n.oid = o.cfgnamespace WHERE n.nspname = 'public'
			UNION ALL SELECT o.oid FROM pg_ts_dict o JOIN pg_namespace n ON n.oid = o.dictnamespace WHERE n.nspname = 'public'
			UNION ALL SELECT o.oid FROM pg_ts_parser o JOIN pg_namespace n ON n.oid = o.prsnamespace WHERE n.nspname = 'public'
			UNION ALL SELECT o.oid FROM pg_ts_template o JOIN pg_namespace n ON n.oid = o.tmplnamespace WHERE n.nspname = 'public'
		) objects`).Scan(&unexpectedObjects); err != nil {
		return err
	}
	if err := q.QueryRow(ctx, `SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname <> $1 AND NOT t.tgisinternal`, migrationTable).Scan(&unexpectedTriggers); err != nil {
		return err
	}
	if err := q.QueryRow(ctx, `SELECT count(*) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname <> $1`, migrationTable).Scan(&unexpectedPolicies); err != nil {
		return err
	}
	if unexpectedTypes != 0 || unexpectedRoutines != 0 || unexpectedObjects != 0 || unexpectedTriggers != 0 || unexpectedPolicies != 0 {
		return fmt.Errorf("untracked schema has %d unexpected user-defined type(s), %d routine(s), %d other object(s), %d trigger(s), and %d row-security policies", unexpectedTypes, unexpectedRoutines, unexpectedObjects, unexpectedTriggers, unexpectedPolicies)
	}
	return nil
}

func verifyMigration001TableFlags(ctx context.Context, q catalogReader) error {
	var unexpected int
	if err := q.QueryRow(ctx, `
		SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
		WHERE n.nspname='public' AND c.relkind IN ('r','p') AND c.relname <> $1
		  AND (c.relispartition OR c.relrowsecurity OR c.relforcerowsecurity OR c.relpersistence <> 'p')`, migrationTable).Scan(&unexpected); err != nil {
		return err
	}
	if unexpected != 0 {
		return fmt.Errorf("untracked schema has %d table(s) with non-migration persistence, partition, or row-security flags", unexpected)
	}
	return nil
}

func classifySeedFootprint(ctx context.Context, q catalogReader) (seedState, error) {
	roles := make(map[string]string)
	roleKeys := []string{"admin", "moderator", "manager", "teacher", "student", "user", "guest"}
	rows, err := q.Query(ctx, `SELECT key, title FROM role WHERE key = ANY($1::text[]) ORDER BY key`, roleKeys)
	if err != nil {
		return seedAmbiguous, err
	}
	for rows.Next() {
		var key, title string
		if err := rows.Scan(&key, &title); err != nil {
			rows.Close()
			return seedAmbiguous, err
		}
		roles[key] = title
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return seedAmbiguous, err
	}
	rows.Close()

	coreID := model.CanonicalCoreService().ID
	var services []string
	rows, err = q.Query(ctx, `SELECT id::text, key, title FROM service WHERE id = $1::uuid OR key = 'core' ORDER BY key, id`, coreID)
	if err != nil {
		return seedAmbiguous, err
	}
	for rows.Next() {
		var id, key, title string
		if err := rows.Scan(&id, &key, &title); err != nil {
			rows.Close()
			return seedAmbiguous, err
		}
		services = append(services, id+"|"+key+"|"+title)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return seedAmbiguous, err
	}
	rows.Close()

	principalIDs := make([]string, 0, len(currentSeedGrants))
	for _, grant := range currentSeedGrants {
		principalIDs = append(principalIDs, grant.principal)
	}
	var assignments []string
	rows, err = q.Query(ctx, `
		SELECT pr.principal_id::text, pr.principal_kind::text, COALESCE(r.key,''),
		       COALESCE(pr.tenant_id::text,''), COALESCE(pr.service_id::text,''),
		       COALESCE(pr.resource_kind,''), COALESCE(pr.resource_id::text,'')
		FROM principal_role pr
		LEFT JOIN role r ON r.id = pr.role_id
		WHERE pr.principal_id::text = ANY($1::text[])
		ORDER BY pr.principal_id, pr.role_id`, principalIDs)
	if err != nil {
		return seedAmbiguous, err
	}
	for rows.Next() {
		var principal, kind, role, tenant, service, resourceKind, resourceID string
		if err := rows.Scan(&principal, &kind, &role, &tenant, &service, &resourceKind, &resourceID); err != nil {
			rows.Close()
			return seedAmbiguous, err
		}
		assignments = append(assignments, strings.Join([]string{principal, kind, role, tenant, service, resourceKind, resourceID}, "|"))
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return seedAmbiguous, err
	}
	rows.Close()

	if len(roles) == 0 && len(services) == 0 && len(assignments) == 0 {
		return seedAbsent, nil
	}
	if isCompleteSeed(roles, services, assignments, currentSeedRoles, currentSeedGrants, false) {
		return seedCurrent, nil
	}
	if isCompleteSeed(roles, services, assignments, managerSeedRoles, managerSeedGrants, true) {
		return seedManager, nil
	}
	return seedAmbiguous, nil
}

func isCompleteSeed(roles map[string]string, services, assignments []string, expectedRoles []seedRole, expectedGrants []seedGrant, allowCurrentModerator bool) bool {
	expected := make(map[string]string, len(expectedRoles)+1)
	for _, role := range expectedRoles {
		expected[role.key] = role.title
	}
	if allowCurrentModerator {
		if title, present := roles["moderator"]; present {
			if title != "Moderator" {
				return false
			}
			expected["moderator"] = "Moderator"
		}
	}
	if len(roles) != len(expected) {
		return false
	}
	for key, title := range expected {
		if roles[key] != title {
			return false
		}
	}
	service := model.CanonicalCoreService()
	if len(services) != 1 || services[0] != service.ID+"|"+service.Key+"|"+service.Title {
		return false
	}
	if len(assignments) != len(expectedGrants) {
		return false
	}
	want := make([]string, 0, len(expectedGrants))
	for _, grant := range expectedGrants {
		want = append(want, strings.Join([]string{grant.principal, "user", grant.role, "00000000-0000-0000-0000-000000000000", service.ID, "global", "00000000-0000-0000-0000-000000000000"}, "|"))
	}
	sort.Strings(want)
	actual := append([]string(nil), assignments...)
	sort.Strings(actual)
	return equalStrings(actual, want)
}

func normalizeSQL(value string) string {
	return strings.Join(strings.Fields(strings.ToLower(value)), "")
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
