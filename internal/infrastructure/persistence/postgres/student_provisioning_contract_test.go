package repo_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/example/ms-rbac-service/internal/domain"
	"github.com/example/ms-rbac-service/internal/infrastructure/client"
	repo "github.com/example/ms-rbac-service/internal/infrastructure/persistence/postgres"
	"github.com/example/ms-rbac-service/internal/usecase"
)

// Losing the reply after commit must leave the same durable result available
// to a newly constructed downstream application, without rewriting assignments.
type lostSignupReceiptACK struct {
	domain.SignupProvisioningRepository
}

var errLostSignupACK = errors.New("test-only reply lost after commit")

func (r lostSignupReceiptACK) ProvisionSignup(ctx context.Context, grant domain.SignupGrant) error {
	if err := r.SignupProvisioningRepository.ProvisionSignup(ctx, grant); err != nil {
		return err
	}
	return errLostSignupACK
}

func TestAuthRBACStudentProvisioningV1Contract(t *testing.T) {
	pool := signupSQLPool(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newApplication := func(repository domain.SignupProvisioningRepository) *usecase.SignupProvisioner {
		verifier, err := client.NewSignupProofVerifier(base64.StdEncoding.EncodeToString(public))
		if err != nil {
			t.Fatal(err)
		}
		return usecase.NewSignupProvisioner(verifier, repository)
	}
	ctx := context.Background()
	grant := signupSQLGrant(signupSQLUUID(t), signupSQLUUID(t))
	// A different scope already present on the principal remains untouched.
	signupSQLFixture(t, pool, grant.PrincipalID, "user", signupSQLUUID(t))
	first := newApplication(lostSignupReceiptACK{repo.NewSignupProvisioningRepository(pool)})
	if err := first.Provision(ctx, grant.Subject, signupSQLProof(private, grant)); !errors.Is(err, errLostSignupACK) {
		t.Fatalf("expected successful commit followed by lost ACK: %v", err)
	}
	committed := signupSQLSnapshot(t, pool, grant.PrincipalID)
	// Reopen the pool as well as verifier/usecase/repository: no local state survives.
	reopened := signupSQLPool(t)
	retry := newApplication(repo.NewSignupProvisioningRepository(reopened))
	fresh := signupSQLGrant(grant.PrincipalID, grant.OperationID)
	for i := 0; i < 2; i++ {
		if err := retry.Provision(ctx, fresh.Subject, signupSQLProof(private, fresh)); err != nil {
			t.Fatalf("committed receipt did not reconstruct success: %v", err)
		}
	}
	if signupSQLSnapshot(t, reopened, grant.PrincipalID) != committed {
		t.Fatal("retry duplicated or rewrote durable state")
	}
	for _, test := range []struct {
		name   string
		change func(*domain.SignupGrant)
	}{
		{"principal", func(g *domain.SignupGrant) { g.PrincipalID = signupSQLUUID(t) }},
		{"role", func(g *domain.SignupGrant) { g.Role = "teacher" }},
		{"principal-kind", func(g *domain.SignupGrant) { g.PrincipalKind = "group" }},
		{"tenant", func(g *domain.SignupGrant) { g.TenantID = signupSQLUUID(t) }},
		{"service", func(g *domain.SignupGrant) { g.ServiceID = signupSQLUUID(t) }},
		{"resource-kind", func(g *domain.SignupGrant) { g.ResourceKind = "course" }},
		{"resource", func(g *domain.SignupGrant) { g.ResourceID = signupSQLUUID(t) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := fresh
			test.change(&changed)
			before := signupSQLSnapshot(t, reopened, grant.PrincipalID, changed.PrincipalID)
			if err := retry.Provision(ctx, changed.Subject, signupSQLProof(private, changed)); !errors.Is(err, domain.ErrSignupConflict) {
				t.Fatalf("changed operation binding must conflict: %v", err)
			}
			if signupSQLSnapshot(t, reopened, grant.PrincipalID, changed.PrincipalID) != before {
				t.Fatal("conflict changed assignment or receipt")
			}
		})
	}
	// The dedicated boundary also rejects a non-student initial operation.
	other := signupSQLGrant(signupSQLUUID(t), signupSQLUUID(t))
	other.Role = "teacher"
	before := signupSQLSnapshot(t, reopened, other.PrincipalID)
	if err := retry.Provision(ctx, other.Subject, signupSQLProof(private, other)); !errors.Is(err, domain.ErrSignupConflict) {
		t.Fatalf("non-student operation accepted: %v", err)
	}
	if signupSQLSnapshot(t, reopened, other.PrincipalID) != before {
		t.Fatal("non-student operation wrote state")
	}
}
