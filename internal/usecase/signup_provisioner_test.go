package usecase

import (
	"context"
	"errors"
	"testing"

	"github.com/example/ms-rbac-service/internal/domain"
)

// These doubles test ordering only; actual Auth signature and SQL proofs are separate.
type signupVerifierSpy struct {
	called bool
	grant  domain.SignupGrant
	err    error
}

func (v *signupVerifierSpy) VerifySignupProof(context.Context, string, []byte) (domain.SignupGrant, error) {
	v.called = true
	return v.grant, v.err
}

type signupRepositorySpy struct {
	verifier *signupVerifierSpy
	calls    int
	t        *testing.T
	err      error
}

func (r *signupRepositorySpy) ProvisionSignup(context.Context, domain.SignupGrant) error {
	if !r.verifier.called {
		r.t.Fatal("storage preceded cryptographic admission")
	}
	r.calls++
	return r.err
}

func TestSignupAdmissionAlwaysPrecedesReceiptAndReplay(t *testing.T) {
	for _, failure := range []error{domain.ErrUnauthenticated, domain.ErrAuthorityUnavailable} {
		v := &signupVerifierSpy{err: failure}
		r := &signupRepositorySpy{verifier: v, t: t}
		if err := NewSignupProvisioner(v, r).Provision(context.Background(), "rbac.assign-role", nil); !errors.Is(err, failure) {
			t.Fatal("proof denial changed")
		}
		if r.calls != 0 {
			t.Fatal("proof denial reached receipt or replay storage")
		}
	}
	grant := domain.SignupGrant{Version: 1, Issuer: domain.SignupIssuer, Audience: domain.SignupAudience, Purpose: domain.SignupPurpose,
		Subject: "rbac.assign-role", OperationID: "00000000-0000-4000-8000-000000000911", PrincipalID: "00000000-0000-4000-8000-000000000901",
		Role: domain.SignupRole, PrincipalKind: domain.SignupKind, TenantID: domain.SignupTenantID, ServiceID: domain.SignupServiceID, ResourceKind: domain.SignupResourceKind, ResourceID: domain.SignupResourceID}
	v := &signupVerifierSpy{grant: grant}
	r := &signupRepositorySpy{verifier: v, t: t}
	uc := NewSignupProvisioner(v, r)
	for i := 0; i < 2; i++ {
		v.called = false
		if err := uc.Provision(context.Background(), grant.Subject, nil); err != nil {
			t.Fatal(err)
		}
		if !v.called {
			t.Fatal("replay skipped authorization")
		}
	}
	if r.calls != 2 {
		t.Fatal("authorized requests did not reach receipt repository")
	}
	v.grant.Role = "invalid"
	if err := uc.Provision(context.Background(), grant.Subject, nil); !errors.Is(err, domain.ErrSignupConflict) {
		t.Fatal("invalid verifier binding accepted")
	}
	if r.calls != 2 {
		t.Fatal("invalid binding reached storage")
	}
	var absent *SignupProvisioner
	if err := absent.Provision(context.Background(), grant.Subject, nil); !errors.Is(err, domain.ErrAuthorityUnavailable) {
		t.Fatal("missing provisioner accepted")
	}
}
