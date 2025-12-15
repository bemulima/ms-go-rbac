//go:build integration
// +build integration

package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/example/ms-rbac-service/internal/app"
)

// Integration test that exercises the public RBAC HTTP contract used by other services.
func TestRBACHTTPFlow(t *testing.T) {
	ts := newTestServer(t)

	permID := createPermission(t, ts, "read", "course")
	assignPermissionToRole(t, ts, "moderator", permID)

	userID := "user-123"
	assignRole(t, ts, userID, "moderator")

	assertCheckRole(t, ts, userID, "moderator", true)
	assertPermissionsList(t, ts, userID, []string{"read:course"})
	assertCheckPermission(t, ts, userID, "read:course", true)
}

func TestAssignsUserRoleForNewPrincipal(t *testing.T) {
	ts := newTestServer(t)
	userID := "new-user-001"

	assignRole(t, ts, userID, "user")

	role := getRole(t, ts, userID)
	if role != "user" {
		t.Fatalf("expected role=user, got %s", role)
	}
}

type testServer struct {
	handler http.Handler
}

func newTestServer(t *testing.T) testServer {
	t.Helper()
	srv, err := app.Bootstrap()
	if err != nil {
		t.Fatalf("bootstrap failed: %v", err)
	}
	return testServer{handler: srv.Handler}
}

func (ts testServer) do(req *http.Request) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	ts.handler.ServeHTTP(rr, req)
	return rr
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
	req := httptest.NewRequest(http.MethodPost, "/api/v1/assign_role", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	resp := ts.do(req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
}

func assertCheckRole(t *testing.T, ts testServer, userID, role string, expected bool) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/check_role_by_user_id?user_id="+userID+"&role="+role, nil)
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
	req := httptest.NewRequest(http.MethodGet, "/api/v1/get_permissions_by_user_id_for_role?user_id="+userID, nil)
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
	req := httptest.NewRequest(http.MethodGet, "/api/v1/check_permission_by_user_id?user_id="+userID+"&permission="+permission, nil)
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
	req := httptest.NewRequest(http.MethodGet, "/api/v1/get_role_by_user_id?user_id="+userID, nil)
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
