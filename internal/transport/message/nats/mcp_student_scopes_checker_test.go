package nats

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/example/ms-rbac-service/internal/domain"
	"github.com/example/ms-rbac-service/internal/domain/model"
	"github.com/example/ms-rbac-service/internal/domain/repository"
	"github.com/example/ms-rbac-service/internal/usecase"
)

type mcpScopesProofFixture struct {
	request string
	proof   domain.MCPStudentScopeProof
	err     error
	calls   int
}

func (f *mcpScopesProofFixture) VerifyMCPStudentScopeProof(_ context.Context, raw string) (domain.MCPStudentScopeProof, error) {
	f.calls++
	f.request = raw
	return f.proof, f.err
}

type mcpScopesSignerFixture struct {
	proof   domain.MCPStudentScopeProof
	raw     string
	allowed []string
	err     error
	calls   int
}

func (f *mcpScopesSignerFixture) SignMCPStudentScopeDecision(proof domain.MCPStudentScopeProof, raw string, allowed []string) (string, error) {
	f.calls++
	f.proof, f.raw, f.allowed = proof, raw, append([]string{}, allowed...)
	if f.err != nil {
		return "", f.err
	}
	return "signed-scope-subset", nil
}

type mcpScopesPermissionFixture struct {
	granted map[string]bool
	queries []string
	err     error
}

func (*mcpScopesPermissionFixture) Create(context.Context, repository.RolePermissionCreate) error {
	return nil
}
func (*mcpScopesPermissionFixture) ListByRoleKey(context.Context, string) ([]model.Permission, error) {
	return nil, nil
}
func (f *mcpScopesPermissionFixture) HasDefaultPermission(_ context.Context, role, action, resourceKind string) (bool, error) {
	f.queries = append(f.queries, role+"/"+action+"/"+resourceKind)
	if f.err != nil {
		return false, f.err
	}
	return role == domain.MCPStudentRole && resourceKind == "" && f.granted[action], nil
}

func mcpScopesTestProof(scopes []string) domain.MCPStudentScopeProof {
	return domain.MCPStudentScopeProof{
		Subject:   "00000000-0000-4000-8000-000000000901",
		JWTID:     "00000000-0000-4000-8000-000000000902",
		Requested: scopes, ProofDigest: "verified-test-digest",
	}
}

func TestMCPStudentScopesCheckerSignsOnlyEachExactDefaultStudentPermission(t *testing.T) {
	requested := []string{domain.MCPStudentCoursesReadScope, domain.MCPStudentProfileReadScope, domain.MCPStudentTasksReadScope}
	verifier := &mcpScopesProofFixture{proof: mcpScopesTestProof(requested)}
	signer := &mcpScopesSignerFixture{}
	permissions := &mcpScopesPermissionFixture{granted: map[string]bool{
		domain.MCPStudentProfileReadPermission: true,
		domain.MCPStudentTasksReadPermission:   true,
	}}
	checker := MCPStudentScopesChecker{
		ProofVerifier: verifier, DecisionSigner: signer,
		Principal: usecase.NewPrincipalPermissionUsecase(reviewerPrincipalRoleFixture{defaultRole: domain.MCPStudentRole}, permissions),
	}
	response := checker.handle(context.Background(), []byte(`{"proof":"auth-signed-exact-scopes"}`))
	if response.Error != "" || response.DecisionJWT != "signed-scope-subset" || verifier.calls != 1 ||
		verifier.request != "auth-signed-exact-scopes" || signer.calls != 1 || signer.raw != verifier.request ||
		!reflect.DeepEqual(signer.allowed, []string{domain.MCPStudentProfileReadScope, domain.MCPStudentTasksReadScope}) ||
		!reflect.DeepEqual(signer.proof.Requested, requested) {
		t.Fatalf("signed RBAC subset not exact: %+v signer=%+v verifier=%+v", response, signer, verifier)
	}
	if !reflect.DeepEqual(permissions.queries, []string{
		"student/mcp.courses.read/", "student/mcp.profile.read/", "student/mcp.tasks.read/",
	}) {
		t.Fatalf("unexpected per-scope RBAC checks: %#v", permissions.queries)
	}
}

func TestMCPStudentScopesCheckerSignsEmptySetForNonStudentNotAdminBypass(t *testing.T) {
	for _, role := range []string{"admin", "STUDENT", ""} {
		signer := &mcpScopesSignerFixture{}
		permissions := &mcpScopesPermissionFixture{granted: map[string]bool{domain.MCPStudentTasksReadPermission: true}}
		checker := MCPStudentScopesChecker{
			ProofVerifier:  &mcpScopesProofFixture{proof: mcpScopesTestProof([]string{domain.MCPStudentTasksReadScope})},
			DecisionSigner: signer,
			Principal:      usecase.NewPrincipalPermissionUsecase(reviewerPrincipalRoleFixture{defaultRole: role}, permissions),
		}
		response := checker.handle(context.Background(), []byte(`{"proof":"verified-scopes"}`))
		if response.Error != "" || response.DecisionJWT != "signed-scope-subset" || signer.calls != 1 ||
			len(signer.allowed) != 0 || len(permissions.queries) != 0 {
			t.Fatalf("role=%q bypassed RBAC: %+v signer=%+v queries=%#v", role, response, signer, permissions.queries)
		}
	}
}

func TestMCPStudentScopesCheckerRejectsUntrustedCallerFieldsAndWriteScopes(t *testing.T) {
	verifier := &mcpScopesProofFixture{proof: mcpScopesTestProof([]string{domain.MCPStudentTasksReadScope})}
	checker := MCPStudentScopesChecker{ProofVerifier: verifier, DecisionSigner: &mcpScopesSignerFixture{}}
	for _, raw := range []string{
		`{}`, `{"student_id":"00000000-0000-4000-8000-000000000901","scopes":["tasks:read"]}`,
		`{"proof":"token","scopes":["tasks:write"]}`, `{"proof":"token","role":"student"}`,
		`{"proof":"token","proof":"other"}`, `{"proof":null}`, `{"proof":"token"} {}`, `[]`,
	} {
		response := checker.handle(context.Background(), []byte(raw))
		if response.DecisionJWT != "" || response.Error != "invalid payload" {
			t.Fatalf("untrusted RPC input reached policy: %s => %+v", raw, response)
		}
	}
	if verifier.calls != 0 {
		t.Fatalf("caller-controlled RPC fields reached verifier: %d", verifier.calls)
	}

	for _, invalidScopes := range [][]string{{"tasks:write"}, {"lessons:read"}, {"tasks:read", "profile:read"}} {
		permissions := &mcpScopesPermissionFixture{granted: map[string]bool{domain.MCPStudentTasksReadPermission: true}}
		signer := &mcpScopesSignerFixture{}
		checker := MCPStudentScopesChecker{
			ProofVerifier: &mcpScopesProofFixture{proof: mcpScopesTestProof(invalidScopes)}, DecisionSigner: signer,
			Principal: usecase.NewPrincipalPermissionUsecase(reviewerPrincipalRoleFixture{defaultRole: "student"}, permissions),
		}
		response := checker.handle(context.Background(), []byte(`{"proof":"verified-but-unsafe"}`))
		if response.DecisionJWT != "" || response.Error == "" || signer.calls != 0 || len(permissions.queries) != 0 {
			t.Fatalf("unsafe requested scopes reached signer: %#v => %+v", invalidScopes, response)
		}
	}
}

func TestMCPStudentScopesCheckerFailsClosedOnProofPolicyOrSignerOutage(t *testing.T) {
	validProof := mcpScopesTestProof([]string{domain.MCPStudentProfileReadScope, domain.MCPStudentTasksReadScope})
	for _, tc := range []struct {
		name          string
		proofErr      error
		roleErr       error
		permissionErr error
		signerErr     error
	}{
		{"invalid signature", errors.New("private proof diagnostic"), nil, nil, nil},
		{"proof key unavailable", domain.ErrAuthorityUnavailable, nil, nil, nil},
		{"ambiguous role", nil, domain.ErrAmbiguousPrincipalRole, nil, nil},
		{"permission store outage", nil, nil, errors.New("private DB diagnostic"), nil},
		{"signer key outage", nil, nil, nil, errors.New("private signer diagnostic")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signer := &mcpScopesSignerFixture{err: tc.signerErr}
			checker := MCPStudentScopesChecker{
				ProofVerifier:  &mcpScopesProofFixture{proof: validProof, err: tc.proofErr},
				DecisionSigner: signer,
				Principal: usecase.NewPrincipalPermissionUsecase(
					reviewerPrincipalRoleFixture{defaultRole: "student", err: tc.roleErr},
					&mcpScopesPermissionFixture{granted: map[string]bool{domain.MCPStudentProfileReadPermission: true}, err: tc.permissionErr},
				),
			}
			response := checker.handle(context.Background(), []byte(`{"proof":"verified"}`))
			if response.DecisionJWT != "" || response.Error == "" || response.Error == "private proof diagnostic" ||
				response.Error == "private DB diagnostic" || response.Error == "private signer diagnostic" {
				t.Fatalf("failure leaked or authorized: %+v", response)
			}
		})
	}
	checker := MCPStudentScopesChecker{}
	if response := checker.handle(context.Background(), []byte(`{"proof":"token"}`)); response.DecisionJWT != "" || response.Error == "" {
		t.Fatalf("missing components accepted: %+v", response)
	}
}
