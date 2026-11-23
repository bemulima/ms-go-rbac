package client

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"reflect"
	"testing"
	"time"

	"github.com/example/ms-rbac-service/internal/domain"
)

func scopeProofForSigner(raw string) domain.MCPStudentScopeProof {
	digest := sha256.Sum256([]byte(raw))
	return domain.MCPStudentScopeProof{
		Subject:     reviewerProofTestSubject,
		JWTID:       reviewerProofTestJTI,
		Requested:   []string{domain.MCPStudentCoursesReadScope, domain.MCPStudentProfileReadScope, domain.MCPStudentTasksReadScope},
		ProofDigest: hex.EncodeToString(digest[:]),
	}
}

func TestMCPStudentScopeDecisionSignsExactRequestedAndAllowedSubset(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	private := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	signer, err := NewMCPStudentScopeDecisionSigner(string(private))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	signer.now = func() time.Time { return now }
	const rawProof = "exact-verified-auth-scope-proof"
	proof := scopeProofForSigner(rawProof)
	allowed := []string{domain.MCPStudentProfileReadScope, domain.MCPStudentTasksReadScope}
	signed, err := signer.SignMCPStudentScopeDecision(proof, rawProof, allowed)
	if err != nil {
		t.Fatal(err)
	}
	claims := verifyReviewerPermissionDecisionForTest(t, key, signed)
	if len(claims) != 12 || claims["iss"] != domain.MCPStudentScopeDecisionIssuer ||
		claims["aud"] != domain.MCPStudentScopeDecisionAudience || claims["sub"] != proof.Subject ||
		claims["typ"] != domain.MCPStudentScopeDecisionType || claims["purpose"] != domain.MCPStudentScopeDecisionPurpose ||
		claims["request_jti"] != proof.JWTID || claims["request_digest"] != proof.ProofDigest ||
		!reflect.DeepEqual(claims["requested_scopes"], []any{"courses:read", "profile:read", "tasks:read"}) ||
		!reflect.DeepEqual(claims["allowed_scopes"], []any{"profile:read", "tasks:read"}) {
		t.Fatalf("wrong signed scope-only claims: %+v", claims)
	}
	decisionJTI, _ := claims["jti"].(string)
	if !validCanonicalReviewerUUID(decisionJTI) || decisionJTI == proof.JWTID ||
		int64(claims["exp"].(float64))-int64(claims["iat"].(float64)) != domain.MCPStudentScopeDecisionTTLSeconds {
		t.Fatalf("invalid response JTI or TTL: %+v", claims)
	}
	// Missing RBAC grants are a signed empty subset, not a role-only ALLOW.
	denied, err := signer.SignMCPStudentScopeDecision(proof, rawProof, []string{})
	if err != nil || !reflect.DeepEqual(verifyReviewerPermissionDecisionForTest(t, key, denied)["allowed_scopes"], []any{}) {
		t.Fatalf("empty RBAC scope subset was not signed: %v", err)
	}
}

func TestMCPStudentScopeDecisionRejectsUnverifiedOrEscalatedSubset(t *testing.T) {
	if signer, err := NewMCPStudentScopeDecisionSigner(""); signer != nil || err != nil {
		t.Fatalf("missing private key should leave signer dormant: %v, %v", signer, err)
	}
	if _, err := NewMCPStudentScopeDecisionSigner("bad-pem"); err == nil {
		t.Fatal("malformed scope key accepted")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	private := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	signer, err := NewMCPStudentScopeDecisionSigner(string(private))
	if err != nil {
		t.Fatal(err)
	}
	const raw = "exact-scope-proof"
	base := scopeProofForSigner(raw)
	validAllowed := []string{domain.MCPStudentProfileReadScope}
	for _, tc := range []struct {
		name     string
		proof    domain.MCPStudentScopeProof
		rawProof string
		allowed  []string
	}{
		{"missing identity", domain.MCPStudentScopeProof{}, raw, validAllowed},
		{"missing raw", base, "", validAllowed},
		{"wrong raw binding", base, "other-raw", validAllowed},
		{"wrong digest", domain.MCPStudentScopeProof{Subject: base.Subject, JWTID: base.JWTID, Requested: base.Requested, ProofDigest: "wrong"}, raw, validAllowed},
		{"nil uncomputed subset", base, raw, nil},
		{"write escalation", base, raw, []string{"tasks:write"}},
		{"unknown read scope", base, raw, []string{"lessons:read"}},
		{"out of order", base, raw, []string{"tasks:read", "profile:read"}},
		{"duplicate allowed", base, raw, []string{"profile:read", "profile:read"}},
		{"unrequested profile", domain.MCPStudentScopeProof{Subject: base.Subject, JWTID: base.JWTID, Requested: []string{"courses:read"}, ProofDigest: base.ProofDigest}, raw, validAllowed},
		{"malformed requested", domain.MCPStudentScopeProof{Subject: base.Subject, JWTID: base.JWTID, Requested: []string{"tasks:write"}, ProofDigest: base.ProofDigest}, raw, []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if signed, err := signer.SignMCPStudentScopeDecision(tc.proof, tc.rawProof, tc.allowed); signed != "" || err == nil {
				t.Fatalf("invalid scope subset signed: %s %v", signed, err)
			}
		})
	}
	var missing *MCPStudentScopeDecisionSigner
	if signed, err := missing.SignMCPStudentScopeDecision(base, raw, validAllowed); signed != "" || err == nil {
		t.Fatalf("nil signer signed scope decision: %q %v", signed, err)
	}
}
