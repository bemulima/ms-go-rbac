package nats

import (
	"context"
	"errors"
	"testing"

	"github.com/example/ms-rbac-service/internal/domain"
	"github.com/example/ms-rbac-service/internal/usecase"
)

type mcpRoleProofVerifierFixture struct {
	proof string
	err   error
	calls int
}

func (f *mcpRoleProofVerifierFixture) VerifyMCPStudentRoleProof(_ context.Context, raw string) (domain.MCPStudentRoleProof, error) {
	f.calls++
	f.proof = raw
	return domain.MCPStudentRoleProof{
		Subject: "00000000-0000-4000-8000-000000000901",
		JWTID: "00000000-0000-4000-8000-000000000902",
	}, f.err
}

type mcpRoleSignerFixture struct {
	proof domain.MCPStudentRoleProof
	raw   string
	allow bool
	calls int
}

func (f *mcpRoleSignerFixture) SignMCPStudentRoleDecision(proof domain.MCPStudentRoleProof, raw string, allowed bool) (string, error) {
	f.calls++
	f.proof, f.raw, f.allow = proof, raw, allowed
	if allowed {
		return "signed-allow", nil
	}
	return "signed-deny", nil
}

func TestMCPStudentRoleCheckerSignsOnlyCurrentDefaultStudent(t *testing.T) {
	for _, tc := range []struct {
		name, role, expected string
		allow                bool
	}{
		{"default student", "student", "signed-allow", true},
		{"admin denied", "admin", "signed-deny", false},
		{"role missing", "", "signed-deny", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verifier, signer := &mcpRoleProofVerifierFixture{}, &mcpRoleSignerFixture{}
			checker := MCPStudentRoleChecker{
				ProofVerifier: verifier, DecisionSigner: signer,
				Principal: usecase.NewPrincipalPermissionUsecase(reviewerPrincipalRoleFixture{defaultRole: tc.role}, reviewerRolePermissionFixture{}),
			}
			response := checker.handle(context.Background(), []byte(`{"proof":"auth-signed-mcp-proof"}`))
			if response.DecisionJWT != tc.expected || response.Error != "" || verifier.calls != 1 ||
				verifier.proof != "auth-signed-mcp-proof" || signer.calls != 1 || signer.raw != verifier.proof ||
				signer.allow != tc.allow || signer.proof.Subject != "00000000-0000-4000-8000-000000000901" {
				t.Fatalf("unexpected exact role decision: %+v verifier=%+v signer=%+v", response, verifier, signer)
			}
		})
	}
}

func TestMCPStudentRoleCheckerRejectsUnsignedAndCallerControlledFields(t *testing.T) {
	verifier := &mcpRoleProofVerifierFixture{}
	checker := MCPStudentRoleChecker{ProofVerifier: verifier, DecisionSigner: &mcpRoleSignerFixture{}}
	for _, raw := range []string{
		`{}`, `{"user_id":"00000000-0000-4000-8000-000000000901","role":"student"}`,
		`{"proof":"x","role":"student"}`, `{"proof":"x","student_id":"other"}`,
		`{"proof":"x","proof":"y"}`, `{"proof":null}`, `{"proof":"x"} {}`,
		`{"proof":"x","scopes":["tasks:write"]}`, `[]`,
	} {
		response := checker.handle(context.Background(), []byte(raw))
		if response.DecisionJWT != "" || response.Error != "invalid payload" {
			t.Fatalf("unsafe input %s produced %+v", raw, response)
		}
	}
	if verifier.calls != 0 {
		t.Fatalf("caller fields reached verifier %d times", verifier.calls)
	}
}

func TestMCPStudentRoleCheckerFailClosedWithoutVerifiedProofOrDefaultRole(t *testing.T) {
	principal := usecase.NewPrincipalPermissionUsecase(reviewerPrincipalRoleFixture{defaultRole: "student"}, reviewerRolePermissionFixture{})
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"untrusted proof", errors.New("signature details")},
		{"unavailable signer authority", domain.ErrAuthorityUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checker := MCPStudentRoleChecker{ProofVerifier: &mcpRoleProofVerifierFixture{err: tc.err}, DecisionSigner: &mcpRoleSignerFixture{}, Principal: principal}
			response := checker.handle(context.Background(), []byte(`{"proof":"bad"}`))
			if response.DecisionJWT != "" || response.Error == "" || response.Error == tc.err.Error() {
				t.Fatalf("unsafe proof generated decision: %+v", response)
			}
		})
	}
	checker := MCPStudentRoleChecker{ProofVerifier: &mcpRoleProofVerifierFixture{}, DecisionSigner: &mcpRoleSignerFixture{},
		Principal: usecase.NewPrincipalPermissionUsecase(reviewerPrincipalRoleFixture{err: domain.ErrAmbiguousPrincipalRole}, reviewerRolePermissionFixture{}),
	}
	response := checker.handle(context.Background(), []byte(`{"proof":"valid"}`))
	if response.DecisionJWT != "" || response.Error != "MCP Student role lookup unavailable" {
		t.Fatalf("ambiguous default assignment was authorized: %+v", response)
	}
	checker.DecisionSigner = nil
	response = checker.handle(context.Background(), []byte(`{"proof":"valid"}`))
	if response.DecisionJWT != "" || response.Error != "MCP Student role lookup unavailable" {
		t.Fatalf("missing key signer was authorized: %+v", response)
	}
}
