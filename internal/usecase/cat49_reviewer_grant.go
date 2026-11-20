package usecase

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"github.com/example/ms-rbac-service/internal/domain/repository"
)

var ErrCAT49ReviewerGrantDenied = errors.New("CAT49 reviewer operator denied")
var cat49UUID = regexp.MustCompile("^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
var cat49Run = regexp.MustCompile("^[a-z0-9]{8,32}$")
var cat49Digest = regexp.MustCompile("^sha256:[0-9a-f]{64}$")
var cat49Database = regexp.MustCompile("^cat49_[a-z0-9_]{4,60}$")

func cat49Hash(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func cat49RegistrationFields(p repository.CAT49RegistrationReceipt) map[string]string {
	return map[string]string{
		"schema": p.Schema, "run_id": p.RunID, "request_id": p.RequestID,
		"principal_id": p.PrincipalID, "auth_database": p.AuthDatabase,
		"intent_digest": p.IntentDigest,
	}
}
func cat49RegistrationSignedFields(p repository.CAT49RegistrationReceipt) map[string]string {
	fields := cat49RegistrationFields(p)
	fields["receipt_digest"] = p.ReceiptDigest
	return fields
}
func cat49MAC(key, body []byte) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(body)
	return "sha256:" + hex.EncodeToString(mac.Sum(nil))
}
func cat49SameDigest(a, b string) bool {
	if !cat49Digest.MatchString(a) || !cat49Digest.MatchString(b) {
		return false
	}
	return hmac.Equal([]byte(a), []byte(b))
}

// VerifyCAT49Registration proves Auth operator issuance, exact disposable owner
// and canonical bytes. A fake RBAC role or arbitrary signed JWT is insufficient.
func VerifyCAT49Registration(raw, key []byte, runID, authDatabase string) (repository.CAT49RegistrationReceipt, error) {
	var proof repository.CAT49RegistrationReceipt
	if len(key) < 32 || len(key) > 4096 || len(raw) > 4096 ||
		!cat49Run.MatchString(runID) || !cat49Database.MatchString(authDatabase) {
		return proof, ErrCAT49ReviewerGrantDenied
	}
	candidate := bytes.TrimSpace(raw)
	if json.Unmarshal(candidate, &proof) != nil {
		return proof, ErrCAT49ReviewerGrantDenied
	}
	canonical, err := json.Marshal(proof)
	if err != nil || !bytes.Equal(candidate, canonical) {
		return proof, ErrCAT49ReviewerGrantDenied
	}
	if proof.Schema != "cat49-disposable-reviewer-registration.v1" ||
		proof.RunID != runID || proof.AuthDatabase != authDatabase ||
		!cat49UUID.MatchString(proof.RequestID) || !cat49UUID.MatchString(proof.PrincipalID) ||
		!cat49Digest.MatchString(proof.IntentDigest) {
		return proof, ErrCAT49ReviewerGrantDenied
	}
	body, _ := json.Marshal(cat49RegistrationFields(proof))
	if !cat49SameDigest(proof.ReceiptDigest, cat49Hash(body)) {
		return proof, ErrCAT49ReviewerGrantDenied
	}
	signed, _ := json.Marshal(cat49RegistrationSignedFields(proof))
	if !cat49SameDigest(proof.Signature, cat49MAC(key, signed)) {
		return proof, ErrCAT49ReviewerGrantDenied
	}
	return proof, nil
}

func ValidateCAT49ReviewerGrantIntent(in repository.CAT49ReviewerGrantIntent) error {
	if !cat49Run.MatchString(in.RunID) || !cat49UUID.MatchString(in.RequestID) ||
		!cat49UUID.MatchString(in.PrincipalID) || !cat49Digest.MatchString(in.AuthReceiptDigest) ||
		len(in.Operator) == 0 || len(in.Operator) > 64 || strings.ContainsAny(in.Operator, " /\\\t\n\r\x00") {
		return ErrCAT49ReviewerGrantDenied
	}
	return nil
}

// GrantCAT49Reviewer never owns Auth registration or any network role API.
// The caller must have a signed, independently reviewed Auth registration proof.
func GrantCAT49Reviewer(ctx context.Context, store repository.CAT49ReviewerGrantStore,
	in repository.CAT49ReviewerGrantIntent) (repository.CAT49ReviewerGrantReceipt, error) {
	if store == nil || ValidateCAT49ReviewerGrantIntent(in) != nil {
		return repository.CAT49ReviewerGrantReceipt{}, ErrCAT49ReviewerGrantDenied
	}
	return store.GrantCAT49Reviewer(ctx, in)
}
func CAT49SignGrantReceipt(p repository.CAT49ReviewerGrantReceipt, key []byte) (repository.CAT49ReviewerGrantReceipt, error) {
	if len(key) < 32 || len(key) > 4096 || p.Schema != "cat49-disposable-reviewer-grant.v1" ||
		p.Role != "moderator" || !cat49Run.MatchString(p.RunID) ||
		!cat49UUID.MatchString(p.RequestID) || !cat49UUID.MatchString(p.PrincipalID) ||
		!cat49Digest.MatchString(p.AuthReceiptDigest) || p.AppliedAt == "" {
		return p, ErrCAT49ReviewerGrantDenied
	}
	fields := map[string]string{
		"schema": p.Schema, "run_id": p.RunID, "request_id": p.RequestID,
		"principal_id": p.PrincipalID, "auth_receipt_digest": p.AuthReceiptDigest,
		"role": p.Role, "operator": p.Operator, "applied_at": p.AppliedAt,
	}
	payload, _ := json.Marshal(fields)
	p.ReceiptDigest = cat49Hash(payload)
	fields["receipt_digest"] = p.ReceiptDigest
	signed, _ := json.Marshal(fields)
	p.Signature = cat49MAC(key, signed)
	return p, nil
}
