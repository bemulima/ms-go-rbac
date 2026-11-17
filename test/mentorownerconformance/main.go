//go:build mentorconformance

// Actual RBAC provider invoked through private pipes by the offline Auth runner.
// The repository below is deliberately a controlled read fixture, not a store.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/example/ms-rbac-service/internal/infrastructure/client"
	inbound "github.com/example/ms-rbac-service/internal/transport/message/nats"
	"github.com/example/ms-rbac-service/internal/usecase"
)

type config struct {
	Operation    string          `json:"operation"`
	Mode         string          `json:"mode"`
	Subject      string          `json:"subject"`
	Body         json.RawMessage `json:"body"`
	LookupPublic string          `json:"lookup_public_key"`
	ReplyPrivate string          `json:"reply_private_key"`
	ReplyPublic  string          `json:"reply_public_key"`
	Proof        string          `json:"proof"`
	GrantPublic  string          `json:"grant_public_key"`
}

type readFixture struct{ mode string }

func (fixture readFixture) GetDefaultRole(ctx context.Context, actor string) (string, error) {
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if fixture.mode == "dependency" {
		return "", errors.New("controlled owner repository failure")
	}
	if fixture.mode == "not_admin" || actor != "11111111-1111-4111-8111-111111111111" {
		return "student", nil
	}
	return "admin", nil
}

func main() {
	var input config
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 1<<20))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil {
		os.Exit(1)
	}
	if decoder.Decode(new(any)) != io.EOF {
		os.Exit(1)
	}
	if input.Operation == "verify_role_proof" {
		verifier, err := client.NewAuthMentorRoleProofVerifier(input.GrantPublic)
		if err != nil {
			os.Exit(1)
		}
		proof, err := verifier.VerifyMentorRoleProof(context.Background(), input.Proof)
		accepted := err == nil && proof.Command.AdminID == "11111111-1111-4111-8111-111111111111" &&
			proof.Command.TargetUserID == "22222222-2222-4222-8222-222222222222" &&
			proof.Command.ApplicationID == "33333333-3333-4333-8333-333333333333" &&
			proof.Command.RequestID == "55555555-5555-4555-8555-555555555555" &&
			proof.Command.Decision == "APPROVE" && proof.Command.ApplicationRevision == 2
		_ = json.NewEncoder(os.Stdout).Encode(struct {
			Accepted bool `json:"accepted"`
		}{accepted})
		return
	}
	if input.Operation != "lookup" {
		os.Exit(1)
	}
	verifier, err := client.NewAuthMentorAdminLookupProofVerifier(input.LookupPublic)
	if err != nil {
		os.Exit(1)
	}
	signer, err := client.NewMentorCanonicalAdminDecisionSigner(input.ReplyPrivate)
	if err != nil {
		os.Exit(1)
	}
	lookup := usecase.NewMentorCanonicalAdminLookup(readFixture{mode: input.Mode})
	handler := &inbound.MentorCanonicalAdminConsumer{ProofVerifier: verifier, Lookup: lookup, DecisionSigner: signer}
	body, err := handler.Handle(context.Background(), input.Subject, input.Body)
	_ = json.NewEncoder(os.Stdout).Encode(struct {
		Body        json.RawMessage `json:"body,omitempty"`
		Unavailable bool            `json:"unavailable"`
	}{Body: body, Unavailable: err != nil})
}
