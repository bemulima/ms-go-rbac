//go:build integration
// +build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"testing"

	repo "github.com/example/ms-rbac-service/internal/infrastructure/persistence/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Reads remain supported; only the test-owned repository fixture may write.
func TestRBACHTTPFlow(t *testing.T) {
	ts := newTestServer(t)
	const action = "d7-native-read"
	const resource = "d7-native-course"
	const userID = "d7000000-0000-0000-0000-000000000001"
	ts.cleanupD7Data(t, action, resource, userID)
	t.Cleanup(func() { ts.cleanupD7Data(t, action, resource, userID) })

	permID := ts.seedReadFixture(t, action, resource, userID)
	ts.assertDeniedWritesUnchanged(t, userID, permID)

	assertCheckRole(t, ts, userID, "moderator", true)
	assertPermissionsList(t, ts, userID, []string{action + ":" + resource})
	assertCheckPermission(t, ts, userID, action+":"+resource, true)
	assertCheckRole(t, ts, userID, "admin", false)
	assertCheckPermission(t, ts, userID, "missing:permission", false)
}

func TestAssignsUserRoleForNewPrincipal(t *testing.T) {
	ts := newTestServer(t)
	const userID = "d7000000-0000-0000-0000-000000000002"
	ts.cleanupD7Data(t, "d7-native-user", "d7-native-user", userID)
	t.Cleanup(func() { ts.cleanupD7Data(t, "d7-native-user", "d7-native-user", userID) })

	// An absent principal must not acquire even STUDENT through legacy HTTP.
	ts.assertDeniedWritesUnchanged(t, userID, "00000000-0000-4000-8000-000000000001")
	if role := getRole(t, ts, userID); role != "" {
		t.Fatalf("denied HTTP write created role %q", role)
	}
	// Positive GET coverage uses the supported repository, never HTTP mutation.
	if err := repo.NewPrincipalRoleRepository(ts.pool).Update(context.Background(), userID, repo.PrincipalRoleUpdate{RoleKey: "user"}); err != nil {
		t.Fatalf("seed test-owned principal role: %v", err)
	}
	ts.assertDeniedWritesUnchanged(t, userID, "00000000-0000-4000-8000-000000000001")

	role := getRole(t, ts, userID)
	if role != "user" {
		t.Fatalf("expected role=user, got %s", role)
	}
}

type testServer struct {
	handler http.Handler
	pool    *pgxpool.Pool
}

func newTestServer(t *testing.T) testServer {
	t.Helper()
	if os.Getenv("DB_DSN") == "" {
		t.Fatal("DB_DSN is required for integration tests")
	}
	if os.Getenv("RBAC_MIGRATION_TEST_ALLOW_CREATE_DATABASE") != "YES" || !httpFixtureDSNAllowed(os.Getenv("DB_DSN")) {
		t.Fatal("HTTP fixture requires the explicitly owned loopback rbac_http_test_<24 hex> database")
	}
	handler, pool := newHTTPHandler(t)
	config, err := pgxpool.ParseConfig(os.Getenv("DB_DSN"))
	if err != nil {
		t.Fatal("invalid HTTP fixture config")
	}
	var database string
	if err := pool.QueryRow(context.Background(), "SELECT current_database()").Scan(&database); err != nil || database != config.ConnConfig.Database {
		t.Fatal("HTTP fixture actual database identity mismatch")
	}
	return testServer{handler: handler, pool: pool}
}

// Matches only the existing CI adapter's random database identity. Never use
// canonical lw_rbac or an arbitrary DB_DSN for fixture setup or cleanup.
func httpFixtureDSNAllowed(dsn string) bool {
	u, err := url.Parse(dsn)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.User == nil || u.Fragment != "" {
		return false
	}
	for key, values := range u.Query() {
		if key != "sslmode" || len(values) != 1 {
			return false
		}
	}
	c, err := pgxpool.ParseConfig(dsn)
	if err != nil || !regexp.MustCompile(`^rbac_http_test_[0-9a-f]{24}$`).MatchString(c.ConnConfig.Database) {
		return false
	}
	loopback := func(host string) bool { return host == "localhost" || net.ParseIP(host).IsLoopback() }
	if !loopback(c.ConnConfig.Host) {
		return false
	}
	for _, fallback := range c.ConnConfig.Fallbacks {
		if !loopback(fallback.Host) {
			return false
		}
	}
	return true
}

func TestHTTPFixtureDSNGuard(t *testing.T) {
	const owned = "postgres://fixture@127.0.0.1:1/rbac_http_test_aaaaaaaaaaaaaaaaaaaaaaaa?sslmode=disable"
	for _, tc := range []struct {
		dsn string
		ok  bool
	}{
		{owned, true},
		{"", false},
		{"postgres://fixture@127.0.0.1:1/lw_rbac", false},
		{"postgres://fixture@127.0.0.1:1/postgres", false},
		{"postgres://fixture@127.0.0.1:1/rbac_http_test_short", false},
		{"postgres://fixture@192.0.2.1:1/rbac_http_test_aaaaaaaaaaaaaaaaaaaaaaaa", false},
		{owned + "&dbname=lw_rbac", false},
		{owned + "&host=192.0.2.1", false},
	} {
		if got := httpFixtureDSNAllowed(tc.dsn); got != tc.ok {
			t.Errorf("fixture DSN guard = %v, want %v", got, tc.ok)
		}
	}
}

func (ts testServer) do(req *http.Request) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	ts.handler.ServeHTTP(rr, req)
	return rr
}

func (ts testServer) cleanupD7Data(t *testing.T, action, resource string, userIDs ...string) {
	t.Helper()
	ctx := context.Background()
	for _, userID := range userIDs {
		if _, err := ts.pool.Exec(ctx, "DELETE FROM principal_role WHERE principal_id = $1", userID); err != nil {
			t.Fatalf("cleanup D7 principal role: %v", err)
		}
	}
	if _, err := ts.pool.Exec(ctx, "DELETE FROM role_permission WHERE permission_id IN (SELECT id FROM permission WHERE action = $1 AND resource_kind = $2)", action, resource); err != nil {
		t.Fatalf("cleanup D7 role permission: %v", err)
	}
	if _, err := ts.pool.Exec(ctx, "DELETE FROM permission WHERE action = $1 AND resource_kind = $2", action, resource); err != nil {
		t.Fatalf("cleanup D7 permission: %v", err)
	}
}

func (ts testServer) seedReadFixture(t *testing.T, action, resource, userID string) string {
	t.Helper()
	ctx := context.Background()
	permission := &repo.Permission{Action: action, ResourceKind: resource}
	if err := repo.NewPermissionRepository(ts.pool).Create(ctx, permission); err != nil {
		t.Fatalf("seed test-owned permission: %v", err)
	}
	if err := repo.NewRolePermissionRepository(ts.pool).Create(ctx, repo.RolePermissionCreate{RoleKey: "moderator", PermissionID: permission.ID}); err != nil {
		t.Fatalf("seed test-owned role permission: %v", err)
	}
	if err := repo.NewPrincipalRoleRepository(ts.pool).Update(ctx, userID, repo.PrincipalRoleUpdate{RoleKey: "moderator"}); err != nil {
		t.Fatalf("seed test-owned principal role: %v", err)
	}
	return permission.ID
}

func (ts testServer) assignmentSnapshot(t *testing.T) map[string]string {
	t.Helper()
	snapshot := make(map[string]string)
	for _, table := range []string{"service", "role", "permission", "role_permission", "principal_role", "principal_override", "superadmin_principal", "signup_provisioning_receipt", "operator_bootstrap_receipt"} {
		var rows string
		// Table identifiers are a fixed test-owned allowlist, never request data.
		query := `SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text), '[]'::jsonb)::text FROM ` + table + ` x`
		if err := ts.pool.QueryRow(context.Background(), query).Scan(&rows); err != nil {
			t.Fatalf("snapshot %s: %v", table, err)
		}
		snapshot[table] = rows
	}
	return snapshot
}

func (ts testServer) assertDeniedWritesUnchanged(t *testing.T, userID, permissionID string) {
	t.Helper()
	before := ts.assignmentSnapshot(t)
	for _, actor := range []string{"anonymous", "STUDENT", "MODERATOR", "ADMIN"} {
		for _, role := range []string{"student", "moderator", "admin"} {
			for _, mutation := range []struct{ method, path, body string }{
				{http.MethodPatch, "/api/v1/principal-role/update", fmt.Sprintf(`{"value":{"user_id":%q,"role":%q}}`, userID, role)},
				{http.MethodPost, "/admin/v1/role-permission", fmt.Sprintf(`{"role_key":%q,"permission_id":%q}`, role, permissionID)},
				{"SET", "/admin/v1/permission", `{"action":"forbidden","resource_kind":"course"}`},
				{http.MethodPost, "/admin/v1/permission", `{"action":"forbidden","resource_kind":"course"}`},
				{"SET", "/admin/v1/role", `{"key":"forbidden","title":"Forbidden"}`},
				{http.MethodPost, "/admin/v1/role", `{"key":"forbidden","title":"Forbidden"}`},
				{http.MethodPut, "/admin/v1/permission/" + permissionID, `{"action":"forbidden"}`},
				{http.MethodPut, "/admin/v1/role/00000000-0000-4000-8000-000000000001", `{"title":"Forbidden"}`},
				{http.MethodDelete, "/admin/v1/role/00000000-0000-4000-8000-000000000001", `{}`},
			} {
				t.Run(actor+"/"+role+"/"+mutation.method+mutation.path, func(t *testing.T) {
					req := httptest.NewRequest(mutation.method, mutation.path, bytes.NewBufferString(mutation.body))
					req.Header.Set("Content-Type", "application/json")
					if actor != "anonymous" {
						// Deliberately forged assertions must never authorize a network write.
						req.Header.Set("X-User-Id", userID)
						req.Header.Set("X-User-Role", actor)
						req.Header.Set("Authorization", "Bearer untrusted-test-assertion")
						req.Header.Set("X-Internal-Token", "untrusted-test-assertion")
					}
					if got := ts.do(req).Code; got != http.StatusForbidden {
						t.Errorf("denied mutation status = %d, want 403", got)
					}
					for table, after := range ts.assignmentSnapshot(t) {
						if after != before[table] {
							t.Errorf("denied request changed %s", table)
						}
					}
				})
			}
		}
	}
}

func assertCheckRole(t *testing.T, ts testServer, userID, role string, expected bool) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/principal-role/get-by-role?user_id="+userID+"&role="+role, nil)
	resp := ts.do(req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
	var payload struct {
		Allowed bool `json:"allowed"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode check role: %v", err)
	}
	if payload.Allowed != expected {
		t.Fatalf("expected allowed=%v, got %v", expected, payload.Allowed)
	}
}

func assertPermissionsList(t *testing.T, ts testServer, userID string, expected []string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/principal-permission/list?user_id="+userID, nil)
	resp := ts.do(req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
	var payload struct {
		Permissions []string `json:"permissions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode permissions: %v", err)
	}
	if len(payload.Permissions) != len(expected) {
		t.Fatalf("expected permissions %v, got %v", expected, payload.Permissions)
	}
	for i, perm := range expected {
		if payload.Permissions[i] != perm {
			t.Fatalf("expected permissions %v, got %v", expected, payload.Permissions)
		}
	}
}

func assertCheckPermission(t *testing.T, ts testServer, userID, permission string, expected bool) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/principal-permission/get-by-permission?user_id="+userID+"&permission="+permission, nil)
	resp := ts.do(req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
	var payload struct {
		Allowed bool `json:"allowed"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode check permission: %v", err)
	}
	if payload.Allowed != expected {
		t.Fatalf("expected allowed=%v, got %v", expected, payload.Allowed)
	}
}

func getRole(t *testing.T, ts testServer, userID string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/principal-role/get?user_id="+userID, nil)
	resp := ts.do(req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
	var payload struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode get role: %v", err)
	}
	return payload.Role
}
