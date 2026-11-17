//go:build mentorscopedreadback

// Offline provider bridge. The real verifier, usecase, signer and handler run
// over private process pipes and a controlled reader, never PostgreSQL/NATS.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"

	"github.com/example/ms-rbac-service/internal/domain"
	"github.com/example/ms-rbac-service/internal/infrastructure/client"
	inbound "github.com/example/ms-rbac-service/internal/transport/message/nats"
	"github.com/example/ms-rbac-service/internal/usecase"
)

type config struct {
	Mode          string          `json:"mode"`
	Subject       string          `json:"subject"`
	Body          json.RawMessage `json:"body"`
	RequestPublic string          `json:"request_public_key"`
	ReplyPrivate  string          `json:"reply_private_key"`
	ReplyPublic   string          `json:"reply_public_key"`
}

type controlledReader struct {
	mode  string
	calls int
}

func (r *controlledReader) ReadMentorRole(ctx context.Context, c domain.MentorRoleCommand) (domain.MentorRoleReadbackResult, error) {
	r.calls++
	if ctx.Err() != nil || r.mode == "dependency" {
		return domain.MentorRoleReadbackResult{}, errors.New("controlled read failure")
	}
	if r.mode == "missing" || r.mode == "superseded" {
		return domain.MentorRoleReadbackResult{}, nil
	}
	want := domain.MentorRoleCommand{Issuer: "ms-go-auth", AdminID: "11111111-1111-4111-8111-111111111111", TargetUserID: "22222222-2222-4222-8222-222222222222", ApplicationID: "33333333-3333-4333-8333-333333333333", ApplicationRevision: 2, Decision: "APPROVE", RequestID: "55555555-5555-4555-8555-555555555555", Role: "mentor", Service: "ms-go-mentor"}
	if r.mode == "inactive3" {
		want.ApplicationRevision = 3
		want.Decision = "SUSPEND"
		want.RequestID = "66666666-6666-4666-8666-666666666666"
	}
	if r.mode == "inactive4" {
		want.ApplicationRevision = 4
		want.Decision = "SUSPEND"
		want.RequestID = "77777777-7777-4777-8777-777777777777"
	}
	digest := sha256.Sum256([]byte(want.Decision + "|" + want.AdminID + "|" + want.ApplicationID + "|" + want.RequestID + "|" + strconv.FormatUint(want.ApplicationRevision-1, 10)))
	want.DecisionDigest = hex.EncodeToString(digest[:])
	if c != want {
		return domain.MentorRoleReadbackResult{}, nil
	}
	return domain.MentorRoleReadbackResult{Confirmed: true, Active: want.Decision == "APPROVE"}, nil
}

func main() {
	var input config
	d := json.NewDecoder(io.LimitReader(os.Stdin, 1<<20))
	d.DisallowUnknownFields()
	if d.Decode(&input) != nil || d.Decode(new(any)) != io.EOF {
		os.Exit(1)
	}
	v, err := client.NewMentorRoleReadbackProofVerifier(input.RequestPublic)
	if err != nil {
		os.Exit(1)
	}
	s, err := client.NewMentorRoleReadbackDecisionSigner(input.ReplyPrivate, input.ReplyPublic)
	if err != nil {
		os.Exit(1)
	}
	r := &controlledReader{mode: input.Mode}
	h := &inbound.MentorRoleReadbackConsumer{ProofVerifier: v, Lookup: usecase.NewMentorRoleReadbackLookup(r), DecisionSigner: s}
	body, err := h.Handle(context.Background(), input.Subject, input.Body)
	if json.NewEncoder(os.Stdout).Encode(struct {
		Body        json.RawMessage `json:"body,omitempty"`
		Unavailable bool            `json:"unavailable"`
		Reads       int             `json:"reads"`
	}{Body: body, Unavailable: err != nil, Reads: r.calls}) != nil {
		os.Exit(1)
	}
}
