package usecase

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/example/ms-rbac-service/internal/domain"
)

func TestMCP53MutationScopesRequireIndependentDefaultStudentPermission(t *testing.T) {
	requested := []string{
		domain.MCPStudentCoursesReadScope,
		domain.MCPStudentInstancesStartScope,
		domain.MCPStudentSubmissionsWriteScope,
		domain.MCPStudentValidationRunScope,
		domain.MCPStudentWorkspaceWriteScope,
	}
	if !domain.ValidMCPStudentScopeSet(requested) ||
		domain.ValidMCPStudentReadScopeSet(requested) ||
		domain.ValidMCPStudentScopeSet([]string{"workspace:write", "workspace:write"}) ||
		domain.ValidMCPStudentScopeSet([]string{"teacher:ask"}) {
		t.Fatal("MCP write grammar or read-only compatibility violated")
	}
	permissions := &mcpReadPermissionFixture{granted: map[string]bool{
		domain.MCPStudentCoursesReadPermission:    true,
		domain.MCPStudentInstancesStartPermission: true,
	}}
	uc := NewPrincipalPermissionUsecase(permissionPrincipalFixture{defaultRole: domain.MCPStudentRole}, permissions)
	allowed, err := uc.AllowedMCPStudentScopes(context.Background(), mcpScopeTestStudent, requested)
	want := []string{domain.MCPStudentCoursesReadScope, domain.MCPStudentInstancesStartScope}
	if err != nil || !reflect.DeepEqual(allowed, want) {
		t.Fatalf("unexpected write scope subset %#v: %v", allowed, err)
	}
	if len(permissions.queries) != len(requested) {
		t.Fatalf("not all requested permissions were checked: %#v", permissions.queries)
	}
	permissions.granted[domain.MCPStudentWorkspaceWritePermission] = true
	allowed, err = uc.AllowedMCPStudentScopes(context.Background(), mcpScopeTestStudent, requested)
	want = append(want, domain.MCPStudentWorkspaceWriteScope)
	if err != nil || !reflect.DeepEqual(allowed, want) {
		t.Fatalf("explicit write permission not granted: %#v: %v", allowed, err)
	}
	permissions.granted[domain.MCPStudentWorkspaceWritePermission] = false
	allowed, err = uc.AllowedMCPStudentScopes(context.Background(), mcpScopeTestStudent, requested)
	if err != nil || len(allowed) != 2 {
		t.Fatalf("revoked permission leaked: %#v: %v", allowed, err)
	}
	permissions.failOn = domain.MCPStudentInstancesStartPermission
	allowed, err = uc.AllowedMCPStudentScopes(context.Background(), mcpScopeTestStudent, requested)
	if len(allowed) != 0 || !errors.Is(err, domain.ErrAuthorityUnavailable) {
		t.Fatalf("RBAC outage permitted partial grant: %#v: %v", allowed, err)
	}
}

func TestMCP53WriteScopeCannotPassLegacyReadOnlyEvaluator(t *testing.T) {
	permissions := &mcpReadPermissionFixture{granted: map[string]bool{
		domain.MCPStudentWorkspaceWritePermission: true,
	}}
	uc := NewPrincipalPermissionUsecase(permissionPrincipalFixture{defaultRole: domain.MCPStudentRole}, permissions)
	if allowed, err := uc.AllowedMCPStudentReadScopes(context.Background(), mcpScopeTestStudent,
		[]string{domain.MCPStudentWorkspaceWriteScope}); len(allowed) != 0 || !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("write scope passed V0 read-only path: %#v, %v", allowed, err)
	}
	if len(permissions.queries) != 0 {
		t.Fatal("V0 read evaluator reached storage for write scope")
	}
}
