//go:build integration
// +build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Integration test that exercises the public RBAC HTTP contract used by other services.
func TestRBACHTTPFlow(t *testing.T) {
	ts := newTestServer(t)
	const action = "d7-native-read"
	const resource = "d7-native-course"
	const userID = "d7000000-0000-0000-0000-000000000001"
	ts.cleanupD7Data(t, action, resource, userID)
	t.Cleanup(func() { ts.cleanupD7Data(t, action, resource, userID) })

	permID := createPermission(t, ts, action, resource)
	assignPermissionToRole(t, ts, "moderator", permID)

	assignRole(t, ts, userID, "moderator")

	assertCheckRole(t, ts, userID, "moderator", true)
	assertPermissionsList(t, ts, userID, []string{action + ":" + resource})
	assertCheckPermission(t, ts, userID, action+":"+resource, true)
}

func TestAssignsUserRoleForNewPrincipal(t *testing.T) {
	ts := newTestServer(t)
	const userID = "d7000000-0000-0000-0000-000000000002"
	ts.cleanupD7Data(t, "d7-native-user", "d7-native-user", userID)
	t.Cleanup(func() { ts.cleanupD7Data(t, "d7-native-user", "d7-native-user", userID) })

	assignRole(t, ts, userID, "user")

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
	handler, pool := newHTTPHandler(t)
	return testServer{handler: handler, pool: pool}
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

func createPermission(t *testing.T, ts testServer, action, resource string) string {
	t.Helper()
	body := fmt.Sprintf(`{"action":"%s","resource_kind":"%s"}`, action, resource)
	req := httptest.NewRequest("SET", "/admin/v1/permission", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	resp := ts.do(req)
	if resp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.Code)
	}
	var payload struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode permission response: %v", err)
	}
	if payload.ID == "" {
		t.Fatalf("permission id is empty")
	}
	return payload.ID
}

func assignPermissionToRole(t *testing.T, ts testServer, roleKey, permissionID string) {
	t.Helper()
	body := fmt.Sprintf(`{"role_key":"%s","permission_id":"%s"}`, roleKey, permissionID)
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/role-permission", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	resp := ts.do(req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
}

func assignRole(t *testing.T, ts testServer, userID, role string) {
	t.Helper()
	body := fmt.Sprintf(`{"value":{"user_id":"%s","role":"%s"}}`, userID, role)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/principal-role/update", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	resp := ts.do(req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
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
