package usecase

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/example/ms-rbac-service/internal/domain"
	"github.com/example/ms-rbac-service/internal/domain/model"
	"github.com/example/ms-rbac-service/internal/domain/repository"
)

const mcpScopeTestStudent = "00000000-0000-4000-8000-0000000009a1"

type mcpReadPermissionFixture struct {
	granted map[string]bool
	queries []string
	failOn  string
}

func (f *mcpReadPermissionFixture) Create(context.Context, repository.RolePermissionCreate) error {
	return nil
}
func (f *mcpReadPermissionFixture) ListByRoleKey(context.Context, string) ([]model.Permission, error) {
	return nil, nil
}
func (f *mcpReadPermissionFixture) HasDefaultPermission(_ context.Context, roleKey, action, resourceKind string) (bool, error) {
	f.queries = append(f.queries, roleKey+"/"+action+"/"+resourceKind)
	if action == f.failOn {
		return false, errors.New("private database error")
	}
	if roleKey != domain.MCPStudentRole || resourceKind != "" {
		return false, nil
	}
	return f.granted[action], nil
}

func TestMCPStudentReadScopesRequireExplicitDefaultRolePermissionForEachScope(t *testing.T) {
	permissions := &mcpReadPermissionFixture{granted: map[string]bool{
		domain.MCPStudentProfileReadPermission: true,
		domain.MCPStudentTasksReadPermission:   true,
	}}
	uc := NewPrincipalPermissionUsecase(permissionPrincipalFixture{defaultRole: "student"}, permissions)
	requested := []string{domain.MCPStudentCoursesReadScope, domain.MCPStudentProfileReadScope, domain.MCPStudentTasksReadScope}
	allowed, err := uc.AllowedMCPStudentReadScopes(context.Background(), mcpScopeTestStudent, requested)
	if err != nil || !reflect.DeepEqual(allowed, []string{domain.MCPStudentProfileReadScope, domain.MCPStudentTasksReadScope}) {
		t.Fatalf("exact allowed subset = %#v, %v", allowed, err)
	}
	wantQueries := []string{
		"student/" + domain.MCPStudentCoursesReadPermission + "/",
		"student/" + domain.MCPStudentProfileReadPermission + "/",
		"student/" + domain.MCPStudentTasksReadPermission + "/",
	}
	if !reflect.DeepEqual(permissions.queries, wantQueries) {
		t.Fatalf("unexpected role, action, order or default resource kind: %#v", permissions.queries)
	}
	// A previously permitted permission can be revoked between requests.
	permissions.granted[domain.MCPStudentProfileReadPermission] = false
	permissions.granted[domain.MCPStudentTasksReadPermission] = false
	allowed, err = uc.AllowedMCPStudentReadScopes(context.Background(), mcpScopeTestStudent, requested)
	if err != nil || len(allowed) != 0 {
		t.Fatalf("revoked permissions were reused: %#v, %v", allowed, err)
	}
}

func TestMCPStudentReadScopesDenyWrongRoleAndAmbiguousDefaultAssignment(t *testing.T) {
	requested := []string{domain.MCPStudentProfileReadScope}
	for _, tc := range []struct {
		name, legacy, defaultRole string
	}{
		{"admin", "", "admin"},
		{"student only at non-default scope", "student", ""},
		{"role not found", "", ""},
		{"case-different student", "", "STUDENT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			permissions := &mcpReadPermissionFixture{granted: map[string]bool{domain.MCPStudentProfileReadPermission: true}}
			uc := NewPrincipalPermissionUsecase(permissionPrincipalFixture{role: tc.legacy, defaultRole: tc.defaultRole}, permissions)
			allowed, err := uc.AllowedMCPStudentReadScopes(context.Background(), mcpScopeTestStudent, requested)
			if err != nil || len(allowed) != 0 || len(permissions.queries) != 0 {
				t.Fatalf("non-student role reached per-scope grants: %#v, %v, %#v", allowed, err, permissions.queries)
			}
		})
	}
	permissions := &mcpReadPermissionFixture{granted: map[string]bool{domain.MCPStudentProfileReadPermission: true}}
	uc := NewPrincipalPermissionUsecase(permissionPrincipalFixture{defaultErr: domain.ErrAmbiguousPrincipalRole}, permissions)
	if allowed, err := uc.AllowedMCPStudentReadScopes(context.Background(), mcpScopeTestStudent, requested); len(allowed) != 0 || !errors.Is(err, domain.ErrAmbiguousPrincipalRole) || len(permissions.queries) != 0 {
		t.Fatalf("ambiguous default role accepted: %#v, %v, %#v", allowed, err, permissions.queries)
	}
}

func TestMCPStudentReadScopesDenyMalformedUnauthorizedAndOutageInputs(t *testing.T) {
	permissions := &mcpReadPermissionFixture{granted: map[string]bool{
		domain.MCPStudentProfileReadPermission: true,
		domain.MCPStudentTasksReadPermission:   true,
	}}
	uc := NewPrincipalPermissionUsecase(permissionPrincipalFixture{defaultRole: "student"}, permissions)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name    string
		ctx     context.Context
		student string
		scopes  []string
	}{
		{"nil context", nil, mcpScopeTestStudent, []string{domain.MCPStudentProfileReadScope}},
		{"cancelled context", ctx, mcpScopeTestStudent, []string{domain.MCPStudentProfileReadScope}},
		{"invalid student", context.Background(), "not-a-uuid", []string{domain.MCPStudentProfileReadScope}},
		{"noncanonical student", context.Background(), "00000000-0000-4000-8000-0000000009A1", []string{domain.MCPStudentProfileReadScope}},
		{"nil scopes", context.Background(), mcpScopeTestStudent, nil},
		{"too many scopes", context.Background(), mcpScopeTestStudent, []string{domain.MCPStudentCoursesReadScope, domain.MCPStudentProfileReadScope, domain.MCPStudentTasksReadScope, "unapproved:read"}},
		{"duplicate scope", context.Background(), mcpScopeTestStudent, []string{domain.MCPStudentProfileReadScope, domain.MCPStudentProfileReadScope}},
		{"not sorted", context.Background(), mcpScopeTestStudent, []string{domain.MCPStudentTasksReadScope, domain.MCPStudentProfileReadScope}},
		{"write scope", context.Background(), mcpScopeTestStudent, []string{"tasks:write"}},
		{"unknown read scope", context.Background(), mcpScopeTestStudent, []string{"notifications:read"}},
		{"different case", context.Background(), mcpScopeTestStudent, []string{"Profile:read"}},
		{"prefix confusion", context.Background(), mcpScopeTestStudent, []string{"profile:read:any"}},
		{"empty scope", context.Background(), mcpScopeTestStudent, []string{""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			allowed, err := uc.AllowedMCPStudentReadScopes(tc.ctx, tc.student, tc.scopes)
			if len(allowed) != 0 || !errors.Is(err, domain.ErrUnauthenticated) {
				t.Fatalf("invalid scopes or subject admitted: %#v, %v", allowed, err)
			}
		})
	}
	if len(permissions.queries) != 0 {
		t.Fatalf("invalid inputs reached permission store: %#v", permissions.queries)
	}
	permissions.failOn = domain.MCPStudentTasksReadPermission
	allowed, err := uc.AllowedMCPStudentReadScopes(context.Background(), mcpScopeTestStudent, []string{domain.MCPStudentProfileReadScope, domain.MCPStudentTasksReadScope})
	if len(allowed) != 0 || err == nil {
		t.Fatalf("partial read scope allowed on permission store outage: %#v, %v", allowed, err)
	}
	var missing *PrincipalPermissionUsecase
	if allowed, err := missing.AllowedMCPStudentReadScopes(context.Background(), mcpScopeTestStudent, []string{domain.MCPStudentProfileReadScope}); len(allowed) != 0 || !errors.Is(err, domain.ErrAuthorityUnavailable) {
		t.Fatalf("missing RBAC usecase authorized: %#v, %v", allowed, err)
	}
	withoutPermissions := NewPrincipalPermissionUsecase(permissionPrincipalFixture{defaultRole: domain.MCPStudentRole}, nil)
	if allowed, err := withoutPermissions.AllowedMCPStudentReadScopes(context.Background(), mcpScopeTestStudent, []string{domain.MCPStudentProfileReadScope}); len(allowed) != 0 || !errors.Is(err, domain.ErrAuthorityUnavailable) {
		t.Fatalf("missing permission store authorized: %#v, %v", allowed, err)
	}
}
