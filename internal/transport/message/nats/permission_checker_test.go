package nats

import (
	"context"
	"errors"
	"testing"

	"github.com/example/ms-rbac-service/internal/domain"
	"github.com/example/ms-rbac-service/internal/domain/model"
	"github.com/example/ms-rbac-service/internal/domain/repository"
	"github.com/example/ms-rbac-service/internal/usecase"
)

type reviewerProofVerifierFixture struct {
	subject string
	proof   string
	err     error
	calls   int
}

func (f *reviewerProofVerifierFixture) VerifyReviewerPermissionProof(_ context.Context, proof string) (domain.ReviewerPermissionProof, error) {
	f.calls++
	f.proof = proof
	return domain.ReviewerPermissionProof{Subject: f.subject, JWTID: "00000000-0000-4000-8000-000000000902", Permission: domain.KnowledgeGraphReviewPermission}, f.err
}

type reviewerDecisionSignerFixture struct {
	proof domain.ReviewerPermissionProof
	raw   string
	allow bool
	calls int
}

func (f *reviewerDecisionSignerFixture) Sign(proof domain.ReviewerPermissionProof, raw string, allowed bool) (string, error) {
	f.calls++
	f.proof, f.raw, f.allow = proof, raw, allowed
	if allowed {
		return "signed-allow-decision", nil
	}
	return "signed-deny-decision", nil
}

type reviewerPrincipalRoleFixture struct {
	defaultRole string
	err         error
}

func (f reviewerPrincipalRoleFixture) Update(context.Context, string, repository.PrincipalRoleUpdate) error {
	return nil
}
func (f reviewerPrincipalRoleFixture) Get(context.Context, string) (string, error) {
	return "", nil
}
func (f reviewerPrincipalRoleFixture) GetDefaultRole(context.Context, string) (string, error) {
	return f.defaultRole, f.err
}

type reviewerRolePermissionFixture struct {
	permissions    []model.Permission
	expectedRole   string
	defaultAllowed bool
	err            error
}

func (f reviewerRolePermissionFixture) Create(context.Context, repository.RolePermissionCreate) error {
	return nil
}
func (f reviewerRolePermissionFixture) ListByRoleKey(context.Context, string) ([]model.Permission, error) {
	return f.permissions, f.err
}
func (f reviewerRolePermissionFixture) HasDefaultPermission(_ context.Context, roleKey, action, resourceKind string) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	if action != domain.KnowledgeGraphReviewPermission || resourceKind != "" ||
		(f.expectedRole != "" && roleKey != f.expectedRole) {
		return false, nil
	}
	return f.defaultAllowed, nil
}

func TestPermissionCheckerAcceptsOnlyVerifiedProofAndFixedPermission(t *testing.T) {
	proof := &reviewerProofVerifierFixture{subject: "00000000-0000-4000-8000-000000000901"}
	permissionUsecase := usecase.NewPrincipalPermissionUsecase(reviewerPrincipalRoleFixture{defaultRole: "reviewer"}, reviewerRolePermissionFixture{
		expectedRole:   "reviewer",
		defaultAllowed: true,
	})
	signer := &reviewerDecisionSignerFixture{}
	checker := PermissionChecker{ProofVerifier: proof, DecisionSigner: signer, Permission: permissionUsecase}
	response := checker.handle(context.Background(), []byte(`{"proof":"signed-assertion"}`))
	if response.DecisionJWT != "signed-allow-decision" || response.Error != "" || proof.calls != 1 || proof.proof != "signed-assertion" ||
		signer.calls != 1 || signer.raw != "signed-assertion" || !signer.allow ||
		signer.proof.Subject != proof.subject || signer.proof.JWTID == "" || signer.proof.Permission != domain.KnowledgeGraphReviewPermission {
		t.Fatalf("signed reviewer request = (%+v, verifier calls=%d, proof=%q, signer=%+v)", response, proof.calls, proof.proof, signer)
	}
}

func TestPermissionCheckerRejectsCallerSuppliedIdentityAndPermission(t *testing.T) {
	proof := &reviewerProofVerifierFixture{subject: "00000000-0000-4000-8000-000000000901"}
	checker := PermissionChecker{ProofVerifier: proof, DecisionSigner: &reviewerDecisionSignerFixture{}}
	for _, payload := range []string{
		`{"user_id":"00000000-0000-4000-8000-000000000901","permission":"knowledge_graph.review"}`,
		`{"proof":"signed-assertion","user_id":"00000000-0000-4000-8000-000000000901"}`,
		`{"proof":"signed-assertion","permission":"knowledge_graph.review"}`,
		`{"proof":"first","proof":"second"}`,
	} {
		response := checker.handle(context.Background(), []byte(payload))
		if response.DecisionJWT != "" || response.Error != "invalid payload" {
			t.Fatalf("payload %s was not rejected strictly: %+v", payload, response)
		}
	}
	if proof.calls != 0 {
		t.Fatalf("invalid caller-controlled payload reached proof verifier %d times", proof.calls)
	}
}

func TestPermissionCheckerFailsClosedForUnavailableOrInvalidProof(t *testing.T) {
	proof := &reviewerProofVerifierFixture{err: domain.ErrAuthorityUnavailable}
	permissionUsecase := usecase.NewPrincipalPermissionUsecase(reviewerPrincipalRoleFixture{defaultRole: "reviewer"}, reviewerRolePermissionFixture{})
	checker := PermissionChecker{ProofVerifier: proof, Permission: permissionUsecase, DecisionSigner: &reviewerDecisionSignerFixture{}}
	response := checker.handle(context.Background(), []byte(`{"proof":"signed-assertion"}`))
	if response.DecisionJWT != "" || response.Error != "permission lookup unavailable" {
		t.Fatalf("missing permission dependency = %+v, want unavailable denial", response)
	}

	proof = &reviewerProofVerifierFixture{err: errors.New("signature detail")}
	checker = PermissionChecker{ProofVerifier: proof, Permission: permissionUsecase, DecisionSigner: &reviewerDecisionSignerFixture{}}
	response = checker.handle(context.Background(), []byte(`{"proof":"invalid-assertion"}`))
	if response.DecisionJWT != "" || response.Error != "permission lookup denied" {
		t.Fatalf("invalid proof response = %+v, want generic denial", response)
	}
	if response.Error == "signature detail" {
		t.Fatal("proof verifier detail leaked to NATS caller")
	}
}

func TestPermissionCheckerMissingOrAmbiguousGrantDenies(t *testing.T) {
	proof := &reviewerProofVerifierFixture{subject: "00000000-0000-4000-8000-000000000901"}
	missing := usecase.NewPrincipalPermissionUsecase(reviewerPrincipalRoleFixture{}, reviewerRolePermissionFixture{
		expectedRole:   "reviewer",
		defaultAllowed: true,
	})
	signer := &reviewerDecisionSignerFixture{}
	checker := PermissionChecker{ProofVerifier: proof, Permission: missing, DecisionSigner: signer}
	response := checker.handle(context.Background(), []byte(`{"proof":"signed-assertion"}`))
	if response.DecisionJWT != "signed-deny-decision" || response.Error != "" || signer.allow {
		t.Fatalf("missing grant response = %+v, want signed denial", response)
	}

	ambiguous := usecase.NewPrincipalPermissionUsecase(reviewerPrincipalRoleFixture{err: domain.ErrAmbiguousPrincipalRole}, reviewerRolePermissionFixture{
		expectedRole:   "reviewer",
		defaultAllowed: true,
	})
	checker.Permission = ambiguous
	response = checker.handle(context.Background(), []byte(`{"proof":"signed-assertion"}`))
	if response.DecisionJWT != "" || response.Error != "permission lookup unavailable" {
		t.Fatalf("ambiguous grant response = %+v, want fail-closed error", response)
	}
}

func TestDecodePermissionCheckRequestRequiresExactlyProof(t *testing.T) {
	for _, payload := range []string{
		`{}`,
		`{"proof":null}`,
		`{"proof":"x","extra":true}`,
		`{"proof":"x"} {}`,
		`[]`,
	} {
		var request permissionCheckRequest
		if err := decodePermissionCheckRequest([]byte(payload), &request); err == nil {
			t.Fatalf("request %s unexpectedly decoded", payload)
		}
	}
}
