package nats

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/example/ms-rbac-service/internal/domain"
	"strings"
	"unicode/utf8"
)

// MentorRoleReadbackConsumer is source-only; it does not register a subscription.
type MentorRoleReadbackConsumer struct {
	ProofVerifier  domain.MentorRoleReadbackProofVerifier
	Lookup         domain.MentorRoleReadbackChecker
	DecisionSigner domain.MentorRoleReadbackDecisionSigner
}

func (c *MentorRoleReadbackConsumer) Handle(ctx context.Context, subject string, body []byte) ([]byte, error) {
	if c == nil || ctx == nil || ctx.Err() != nil || subject != domain.MentorRoleReadbackSubject || len(body) == 0 || len(body) > domain.MentorRoleReadbackMaxEnvelopeBytes || !utf8.Valid(body) {
		return nil, domain.ErrAuthorityUnavailable
	}
	if missingMentorAdminDependency(c.ProofVerifier) || missingMentorAdminDependency(c.Lookup) || missingMentorAdminDependency(c.DecisionSigner) {
		return nil, domain.ErrAuthorityUnavailable
	}
	var request permissionCheckRequest
	if decodePermissionCheckRequest(body, &request) != nil {
		return nil, domain.ErrAuthorityUnavailable
	}
	proof, err := c.ProofVerifier.VerifyMentorRoleReadbackProof(ctx, subject, request.Proof)
	if err != nil || ctx.Err() != nil || !readbackProofMatchesRequest(proof, subject, request.Proof) {
		return nil, domain.ErrAuthorityUnavailable
	}
	result, err := c.Lookup.Check(ctx, proof.Command)
	if err != nil || ctx.Err() != nil || !domain.ValidMentorRoleReadbackResult(proof.Command, result) {
		return nil, domain.ErrAuthorityUnavailable
	}
	// Reauthenticate the same original bytes after the snapshot. A signature
	// over a different nonce, command, expiry or encoding cannot be substituted.
	current, err := c.ProofVerifier.VerifyMentorRoleReadbackProof(ctx, subject, request.Proof)
	if err != nil || ctx.Err() != nil || current != proof {
		return nil, domain.ErrAuthorityUnavailable
	}
	decision, err := c.DecisionSigner.Sign(ctx, proof, result)
	if err != nil || ctx.Err() != nil || decision == "" || len(decision) > domain.MentorRoleReadbackMaxTokenBytes {
		return nil, domain.ErrAuthorityUnavailable
	}
	response, err := json.Marshal(struct {
		DecisionJWT string `json:"decision_jwt"`
	}{DecisionJWT: decision})
	if err != nil || ctx.Err() != nil || len(response) > domain.MentorRoleReadbackMaxEnvelopeBytes {
		return nil, domain.ErrAuthorityUnavailable
	}
	return response, nil
}

func readbackProofMatchesRequest(p domain.MentorRoleReadbackProof, subject, raw string) bool {
	digest := sha256.Sum256([]byte(raw))
	return p.Subject == subject && domain.ValidMentorRoleCommand(p.Command) && domain.ValidPrincipalID(p.JWTID) && p.JWTID == strings.ToLower(p.JWTID) && p.ProofDigest == hex.EncodeToString(digest[:])
}
