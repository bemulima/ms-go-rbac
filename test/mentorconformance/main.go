//go:build mentorconformance

// Offline, build-tag-only consumer of the actual Auth issuer's bytes. The
// planner below remains pure: no database, broker or live role is touched.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/example/ms-rbac-service/internal/domain"
	"github.com/example/ms-rbac-service/internal/infrastructure/client"
)

const (
	adminID                = "11111111-1111-4111-8111-111111111111"
	targetID               = "22222222-2222-4222-8222-222222222222"
	applicationID          = "33333333-3333-4333-8333-333333333333"
	approveRequest         = "55555555-5555-4555-8555-555555555555"
	suspendPendingRequest  = "66666666-6666-4666-8666-666666666666"
	suspendApprovedRequest = "77777777-7777-4777-8777-777777777777"
)

type envelope struct {
	PublicKey string            `json:"public_key"`
	Proofs    map[string]string `json:"proofs"`
}

func expected(decision string, revision uint64, requestID string) domain.MentorRoleCommand {
	digest := sha256.Sum256([]byte(decision + "|" + adminID + "|" + applicationID + "|" + requestID + "|" + strconv.FormatUint(revision-1, 10)))
	return domain.MentorRoleCommand{Issuer: "ms-go-auth", AdminID: adminID, TargetUserID: targetID, ApplicationID: applicationID, ApplicationRevision: revision, Decision: decision, RequestID: requestID, DecisionDigest: hex.EncodeToString(digest[:]), Role: "mentor", Service: "ms-go-mentor"}
}

func snapshot(fence domain.MentorRoleFence, receipt *domain.MentorRoleCommandReceipt) domain.MentorRoleSnapshot {
	app, target := fence, fence
	return domain.MentorRoleSnapshot{ApplicationFence: &app, TargetFence: &target, Receipt: receipt}
}

func verify() error {
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 65537))
	decoder.DisallowUnknownFields()
	var wire envelope
	if err := decoder.Decode(&wire); err != nil || len(wire.Proofs) != 4 {
		return errors.New("invalid offline fixture envelope")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("trailing offline fixture data")
	}
	verifier, err := client.NewAuthMentorRoleProofVerifier(wire.PublicKey)
	if err != nil {
		return errors.New("actual RBAC verifier construction failed")
	}
	commands := map[string]domain.MentorRoleCommand{
		"approve":          expected("APPROVE", 2, approveRequest),
		"approve_retry":    expected("APPROVE", 2, approveRequest),
		"suspend_pending":  expected("SUSPEND", 3, suspendPendingRequest),
		"suspend_approved": expected("SUSPEND", 4, suspendApprovedRequest),
	}
	proofs := make(map[string]domain.MentorRoleProof, len(commands))
	ctx := context.Background()
	for name, command := range commands {
		proof, verifyErr := verifier.VerifyMentorRoleProof(ctx, wire.Proofs[name])
		digest := sha256.Sum256([]byte(wire.Proofs[name]))
		if verifyErr != nil || proof.Command != command || proof.ProofDigest != hex.EncodeToString(digest[:]) || proof.ExpiresAt-proof.IssuedAt != 30 {
			return fmt.Errorf("real producer-consumer binding failed: %s", name)
		}
		proofs[name] = proof
	}
	if proofs["approve"].JWTID == proofs["approve_retry"].JWTID || proofs["approve"].ProofDigest == proofs["approve_retry"].ProofDigest {
		return errors.New("fresh assertion identity not independent from command identity")
	}
	approved, err := domain.PlanMentorRoleCommand(proofs["approve"].Command, domain.MentorRoleSnapshot{})
	if err != nil || !approved.Write || approved.Replay || !approved.Current.Active || approved.Current.Suspended {
		return errors.New("approval planner result failed")
	}
	replayed, err := domain.PlanMentorRoleCommand(proofs["approve_retry"].Command, snapshot(approved.Current, &approved.Receipt))
	if err != nil || !replayed.Replay || replayed.Write || !replayed.Current.Active {
		return errors.New("idempotent command replay failed")
	}
	suspended, err := domain.PlanMentorRoleCommand(proofs["suspend_pending"].Command, snapshot(approved.Current, nil))
	if err != nil || !suspended.Write || suspended.Current.Active || !suspended.Current.Suspended {
		return errors.New("suspension planner result failed")
	}
	historical, err := domain.PlanMentorRoleCommand(proofs["approve_retry"].Command, snapshot(suspended.Current, &approved.Receipt))
	if err != nil || !historical.Replay || historical.Write || historical.Current.Active || !historical.Receipt.Applied.Active {
		return errors.New("historical receipt confused with current authority")
	}
	tombstone, err := domain.PlanMentorRoleCommand(proofs["suspend_pending"].Command, domain.MentorRoleSnapshot{})
	if err != nil || !tombstone.Write || tombstone.Current.Active || !tombstone.Current.Suspended {
		return errors.New("revoke-first tombstone failed")
	}
	if _, err = domain.PlanMentorRoleCommand(proofs["approve"].Command, snapshot(tombstone.Current, nil)); !errors.Is(err, domain.ErrMentorRoleStaleRevision) {
		return errors.New("delayed approval escaped revocation fence")
	}
	suspendedApproved, err := domain.PlanMentorRoleCommand(proofs["suspend_approved"].Command, snapshot(approved.Current, nil))
	if err != nil || !suspendedApproved.Write || suspendedApproved.Current.Active || !suspendedApproved.Current.Suspended {
		return errors.New("approved-branch suspension failed")
	}
	parts := strings.Split(wire.Proofs["approve"], ".")
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) == 0 {
		return errors.New("unexpected signature fixture")
	}
	signature[0] ^= 1
	parts[2] = base64.RawURLEncoding.EncodeToString(signature)
	if _, err = verifier.VerifyMentorRoleProof(ctx, strings.Join(parts, ".")); err == nil {
		return errors.New("tampered signature accepted")
	}
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return errors.New("negative fixture key generation failed")
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&wrongKey.PublicKey)
	if err != nil {
		return errors.New("negative fixture key encoding failed")
	}
	wrongVerifier, err := client.NewAuthMentorRoleProofVerifier(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})))
	if err != nil {
		return errors.New("negative verifier construction failed")
	}
	if _, err = wrongVerifier.VerifyMentorRoleProof(ctx, wire.Proofs["approve"]); err == nil {
		return errors.New("unrelated signer accepted")
	}
	// A slow run must not pass the negative checks merely because every proof
	// expired. Confirm the unchanged proof is still valid with its actual key.
	if _, err = verifier.VerifyMentorRoleProof(ctx, wire.Proofs["approve"]); err != nil {
		return errors.New("valid control proof no longer admissible after negative checks")
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		Status string `json:"status"`
		Proofs int    `json:"proofs"`
		Checks int    `json:"checks"`
	}{Status: "PASS", Proofs: len(proofs), Checks: 8})
}

func main() {
	if err := verify(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
