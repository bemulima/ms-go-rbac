package usecase

import (
	"context"
	"errors"
	"testing"

	"github.com/example/ms-rbac-service/internal/domain"
	"github.com/example/ms-rbac-service/internal/domain/model"
	"github.com/example/ms-rbac-service/internal/domain/repository"
)

type permissionPrincipalFixture struct {
	role        string
	defaultRole string
	defaultErr  error
}

func (f permissionPrincipalFixture) Update(context.Context, string, repository.PrincipalRoleUpdate) error {
	return nil
}
func (f permissionPrincipalFixture) Get(context.Context, string) (string, error) { return f.role, nil }
func (f permissionPrincipalFixture) GetDefaultRole(context.Context, string) (string, error) {
	return f.defaultRole, f.defaultErr
}

type permissionRoleFixture struct {
	permissions          []model.Permission
	expectedRole         string
	defaultAllowed       bool
	defaultPermissionErr error
}

func (f permissionRoleFixture) Create(context.Context, repository.RolePermissionCreate) error {
	return nil
}
func (f permissionRoleFixture) ListByRoleKey(context.Context, string) ([]model.Permission, error) {
	return f.permissions, nil
}
func (f permissionRoleFixture) HasDefaultPermission(_ context.Context, roleKey, action, resourceKind string) (bool, error) {
	if f.defaultPermissionErr != nil {
		return false, f.defaultPermissionErr
	}
	if action != domain.KnowledgeGraphReviewPermission || resourceKind != "" ||
		(f.expectedRole != "" && roleKey != f.expectedRole) {
		return false, nil
	}
	return f.defaultAllowed, nil
}

func TestPrincipalPermissionUsecaseChecksExactPermissionIdentifier(t *testing.T) {
	usecase := NewPrincipalPermissionUsecase(permissionPrincipalFixture{role: "reviewer"}, permissionRoleFixture{
		permissions: []model.Permission{{Action: "knowledge_graph.review"}, {Action: "course", ResourceKind: "read"}},
	})
	for _, tc := range []struct {
		permission string
		want       bool
	}{
		{"knowledge_graph.review", true},
		{"knowledge_graph.publish", false},
		{"course:read", true},
		{"", false},
	} {
		got, err := usecase.GetByPermission(context.Background(), "reviewer-id", tc.permission)
		if err != nil || got != tc.want {
			t.Fatalf("GetByPermission(%q) = (%v, %v), want (%v, nil)", tc.permission, got, err, tc.want)
		}
	}
}

func TestPrincipalPermissionUsecaseChecksFixedReviewerPermissionAtDefaultScope(t *testing.T) {
	principalID := "00000000-0000-4000-8000-000000000901"
	usecase := NewPrincipalPermissionUsecase(permissionPrincipalFixture{role: "legacy-other-scope", defaultRole: "reviewer"}, permissionRoleFixture{
		expectedRole:   "reviewer",
		defaultAllowed: true,
		permissions: []model.Permission{
			{Action: "knowledge_graph.review"},
			{Action: "knowledge_graph.review", ResourceKind: "catalog"},
		},
	})
	allowed, err := usecase.HasKnowledgeGraphReview(context.Background(), principalID)
	if err != nil || !allowed {
		t.Fatalf("HasKnowledgeGraphReview() = (%v, %v), want (true, nil)", allowed, err)
	}

	withoutDefaultRole := NewPrincipalPermissionUsecase(permissionPrincipalFixture{role: "reviewer"}, permissionRoleFixture{
		permissions: []model.Permission{{Action: "knowledge_graph.review"}},
	})
	allowed, err = withoutDefaultRole.HasKnowledgeGraphReview(context.Background(), principalID)
	if err != nil || allowed {
		t.Fatalf("non-default assignment granted reviewer entitlement: (%v, %v)", allowed, err)
	}

	withoutExactPermission := NewPrincipalPermissionUsecase(permissionPrincipalFixture{defaultRole: "reviewer"}, permissionRoleFixture{
		expectedRole: "reviewer",
		permissions:  []model.Permission{{Action: "knowledge_graph.review", ResourceKind: "catalog"}, {Action: "knowledge_graph.review_extra"}},
	})
	allowed, err = withoutExactPermission.HasKnowledgeGraphReview(context.Background(), principalID)
	if err != nil || allowed {
		t.Fatalf("non-exact permission granted reviewer entitlement: (%v, %v)", allowed, err)
	}
}

func TestPrincipalPermissionUsecaseFailsClosedOnInvalidSubjectOrAmbiguousRole(t *testing.T) {
	validID := "00000000-0000-4000-8000-000000000901"
	uc := NewPrincipalPermissionUsecase(permissionPrincipalFixture{defaultRole: "reviewer"}, permissionRoleFixture{
		expectedRole:   "reviewer",
		defaultAllowed: true,
	})
	if allowed, err := uc.HasKnowledgeGraphReview(context.Background(), "reviewer-id"); allowed || !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("invalid subject = (%v, %v), want denial", allowed, err)
	}
	ambiguous := NewPrincipalPermissionUsecase(permissionPrincipalFixture{defaultErr: domain.ErrAmbiguousPrincipalRole}, permissionRoleFixture{
		expectedRole:   "reviewer",
		defaultAllowed: true,
	})
	if allowed, err := ambiguous.HasKnowledgeGraphReview(context.Background(), validID); allowed || !errors.Is(err, domain.ErrAmbiguousPrincipalRole) {
		t.Fatalf("ambiguous default role = (%v, %v), want fail-closed error", allowed, err)
	}
}

func TestReviewerSuperAdminRequiresExactVerifiedDefaultRole(t *testing.T) {
	const id = "00000000-0000-4000-8000-000000000901"
	for _, tc := range []struct {
		role, defaultRole string
		want              bool
	}{
		{"", "admin", true}, {"admin", "student", false}, {"admin", "", false},
		{"", "ADMIN", false}, {"", " admin", false}, {"", "moderator", false},
	} {
		uc := NewPrincipalPermissionUsecase(permissionPrincipalFixture{role: tc.role, defaultRole: tc.defaultRole}, permissionRoleFixture{})
		got, err := uc.HasKnowledgeGraphReview(context.Background(), id)
		if err != nil || got != tc.want {
			t.Fatalf("role=%q default=%q got=%v err=%v", tc.role, tc.defaultRole, got, err)
		}
	}
}
