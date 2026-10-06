package nats

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/example/ms-rbac-service/internal/domain"
	"github.com/example/ms-rbac-service/internal/infrastructure/client"
	"github.com/example/ms-rbac-service/internal/usecase"
)

type signupMessageRepositorySpy struct {
	calls int
	err   error
}

func (r *signupMessageRepositorySpy) ProvisionSignup(context.Context, domain.SignupGrant) error {
	r.calls++
	return r.err
}

// Exercises the production callback's decision with local unit keys and a storage spy.
// No broker authentication or real Auth issuance is claimed by this unit boundary.
func TestRoleAssignerHasOnlySignedStudentMutationPath(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("cannot generate local unit key")
	}
	verifier, err := client.NewSignupProofVerifier(base64.StdEncoding.EncodeToString(public))
	if err != nil {
		t.Fatal(err)
	}
	repository := &signupMessageRepositorySpy{}
	assigner := RoleAssigner{Subject: "rbac.assign-role", SignupUC: usecase.NewSignupProvisioner(verifier, repository)}
	for _, data := range [][]byte{nil, []byte(`{"user_id":"00000000-0000-4000-8000-000000000901","role":"student","caller":"auth"}`), []byte(`{"key_id":"auth-signup-v1","payload":"!","signature":"!"}`)} {
		if response := assigner.handle(context.Background(), assigner.Subject, data); response.OK || response.Error != "signup provisioning denied" {
			t.Fatal("missing/malformed proof accepted")
		}
	}
	if repository.calls != 0 {
		t.Fatal("unsigned caller reached storage")
	}
	now := time.Now().Unix()
	grant := domain.SignupGrant{Version: 1, Issuer: domain.SignupIssuer, Audience: domain.SignupAudience, Purpose: domain.SignupPurpose,
		Subject: assigner.Subject, OperationID: "00000000-0000-4000-8000-000000000911", PrincipalID: "00000000-0000-4000-8000-000000000901", Role: domain.SignupRole,
		PrincipalKind: domain.SignupKind, TenantID: domain.SignupTenantID, ServiceID: domain.SignupServiceID, ResourceKind: domain.SignupResourceKind, ResourceID: domain.SignupResourceID, IssuedAt: now, ExpiresAt: now + 60}
	payload, _ := json.Marshal(grant)
	proof, _ := json.Marshal(map[string]string{"key_id": domain.SignupProofKeyID, "payload": base64.StdEncoding.EncodeToString(payload), "signature": base64.StdEncoding.EncodeToString(ed25519.Sign(private, payload))})
	if response := assigner.handle(context.Background(), assigner.Subject, proof); !response.OK {
		t.Fatal("signed canonical student request rejected")
	}
	if repository.calls != 1 {
		t.Fatal("signed request did not reach accepted application boundary")
	}
	if response := assigner.handle(context.Background(), "other.subject", proof); response.OK {
		t.Fatal("actual subject mismatch accepted")
	}
	if repository.calls != 1 {
		t.Fatal("subject mismatch reached storage")
	}
	repository.err = domain.ErrSignupConflict
	if response := assigner.handle(context.Background(), assigner.Subject, proof); response.OK || response.Error != "signup provisioning conflict" {
		t.Fatal("conflict ACK changed")
	}
	repository.err = errors.New("private database detail")
	if response := assigner.handle(context.Background(), assigner.Subject, proof); response.OK || response.Error != "signup provisioning failed" {
		t.Fatal("dependency error leaked")
	}
	if response := (RoleAssigner{Subject: assigner.Subject}).handle(context.Background(), assigner.Subject, proof); response.OK || response.Error != "signup provisioning unavailable" {
		t.Fatal("missing application dependency accepted")
	}
}
