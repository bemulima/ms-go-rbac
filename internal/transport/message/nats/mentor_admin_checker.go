package nats

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"

	"github.com/example/ms-rbac-service/internal/domain"
)

// MentorCanonicalAdminConsumer is an unmounted, read-only request handler.
// It has no Listen method and no mutation, legacy scope-fallback or cache port.
type MentorCanonicalAdminConsumer struct {
	ProofVerifier  domain.MentorAdminLookupProofVerifier
	Lookup         domain.MentorCanonicalAdminChecker
	DecisionSigner domain.MentorCanonicalAdminDecisionSigner
}

func (consumer *MentorCanonicalAdminConsumer) Handle(ctx context.Context, actualSubject string, body []byte) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || consumer == nil || actualSubject != domain.MentorCanonicalAdminSubject || len(body) == 0 || len(body) > domain.MentorAdminLookupMaxEnvelopeBytes {
		return nil, domain.ErrAuthorityUnavailable
	}
	if missingMentorAdminDependency(consumer.ProofVerifier) || missingMentorAdminDependency(consumer.Lookup) || missingMentorAdminDependency(consumer.DecisionSigner) {
		return nil, domain.ErrAuthorityUnavailable
	}
	// Only the strict one-proof envelope decoder is shared with the existing
	// read path. Its reviewer verifier, permission usecase and signer are not.
	var request permissionCheckRequest
	if decodePermissionCheckRequest(body, &request) != nil {
		return nil, domain.ErrAuthorityUnavailable
	}
	proof, err := consumer.ProofVerifier.VerifyMentorAdminLookupProof(ctx, actualSubject, request.Proof)
	if err != nil || ctx.Err() != nil || !mentorAdminProofMatchesRequest(proof, actualSubject, request.Proof) {
		return nil, domain.ErrAuthorityUnavailable
	}
	allowed, err := consumer.Lookup.Check(ctx, proof.ActorID)
	if err != nil || ctx.Err() != nil {
		return nil, domain.ErrAuthorityUnavailable
	}
	// The exact original proof is reauthenticated after the read; an expired
	// request or changed recovered binding can never produce a signed result.
	current, err := consumer.ProofVerifier.VerifyMentorAdminLookupProof(ctx, actualSubject, request.Proof)
	if err != nil || ctx.Err() != nil || current != proof {
		return nil, domain.ErrAuthorityUnavailable
	}
	decision, err := consumer.DecisionSigner.Sign(ctx, current, allowed)
	if err != nil || ctx.Err() != nil || decision == "" || len(decision) > domain.MentorAdminLookupMaxTokenBytes {
		return nil, domain.ErrAuthorityUnavailable
	}
	response, err := json.Marshal(struct {
		DecisionJWT string `json:"decision_jwt"`
	}{DecisionJWT: decision})
	if err != nil || ctx.Err() != nil || len(response) > domain.MentorAdminLookupMaxEnvelopeBytes {
		return nil, domain.ErrAuthorityUnavailable
	}
	return response, nil
}

func mentorAdminProofMatchesRequest(proof domain.MentorAdminLookupProof, subject, raw string) bool {
	digest := sha256.Sum256([]byte(raw))
	return proof.Subject == subject && domain.ValidPrincipalID(proof.ActorID) && proof.ActorID == strings.ToLower(proof.ActorID) && domain.ValidPrincipalID(proof.JWTID) && proof.JWTID == strings.ToLower(proof.JWTID) && proof.ProofDigest == hex.EncodeToString(digest[:])
}

func missingMentorAdminDependency(dependency any) bool {
	if dependency == nil {
		return true
	}
	value := reflect.ValueOf(dependency)
	switch value.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return value.IsNil()
	default:
		return false
	}
}
