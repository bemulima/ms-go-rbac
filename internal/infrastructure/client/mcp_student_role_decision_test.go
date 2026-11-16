package client

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"testing"
	"time"

	"github.com/example/ms-rbac-service/internal/domain"
)

func TestMCPStudentRoleDecisionSignerBindsFreshRequestAndRole(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	signer, err := NewMCPStudentRoleDecisionSigner(string(privatePEM))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	signer.now = func() time.Time { return now }
	proof := domain.MCPStudentRoleProof{Subject: reviewerProofTestSubject, JWTID: reviewerProofTestJTI}
	const raw = "exact-auth-proof"
	jwt, err := signer.SignMCPStudentRoleDecision(proof, raw, true)
	if err != nil {
		t.Fatal(err)
	}
	claims := verifyReviewerPermissionDecisionForTest(t, key, jwt)
	digest := sha256.Sum256([]byte(raw))
	if len(claims) != 12 || claims["iss"] != domain.MCPStudentRoleDecisionIssuer ||
		claims["aud"] != domain.MCPStudentRoleDecisionAudience || claims["sub"] != proof.Subject ||
		claims["typ"] != domain.MCPStudentRoleDecisionType || claims["purpose"] != domain.MCPStudentRoleDecisionPurpose ||
		claims["role"] != domain.MCPStudentRole || claims["decision"] != "ALLOW" ||
		claims["request_jti"] != proof.JWTID || claims["request_digest"] != hex.EncodeToString(digest[:]) {
		t.Fatalf("wrong signed role-only claims: %+v", claims)
	}
	decisionJTI, _ := claims["jti"].(string)
	if !domain.ValidPrincipalID(decisionJTI) || decisionJTI == proof.JWTID {
		t.Fatal("invalid/reused response jti")
	}
	if int64(claims["exp"].(float64))-int64(claims["iat"].(float64)) != domain.MCPStudentRoleDecisionTTLSeconds {
		t.Fatal("decision TTL mismatch")
	}
	denied, err := signer.SignMCPStudentRoleDecision(proof, raw, false)
	if err != nil || verifyReviewerPermissionDecisionForTest(t, key, denied)["decision"] != "DENY" {
		t.Fatalf("signed denial failed: %v", err)
	}
}

func TestMCPStudentRoleDecisionSignerFailsClosed(t *testing.T) {
	if signer, err := NewMCPStudentRoleDecisionSigner(""); signer != nil || err != nil {
		t.Fatalf("missing key should disable signer: %v %v", signer, err)
	}
	if _, err := NewMCPStudentRoleDecisionSigner("bad-pem"); err == nil {
		t.Fatal("malformed signing key accepted")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	signer, err := NewMCPStudentRoleDecisionSigner(string(privatePEM))
	if err != nil {
		t.Fatal(err)
	}
	for _, proof := range []domain.MCPStudentRoleProof{
		{},
		{Subject: "00000000-0000-0000-0000-000000000000", JWTID: reviewerProofTestJTI},
		{Subject: reviewerProofTestSubject, JWTID: "not-jti"},
	} {
		if _, err := signer.SignMCPStudentRoleDecision(proof, "raw", true); err == nil {
			t.Fatalf("invalid proof %+v accepted", proof)
		}
	}
	if _, err := signer.SignMCPStudentRoleDecision(domain.MCPStudentRoleProof{Subject: reviewerProofTestSubject, JWTID: reviewerProofTestJTI}, "", true); err == nil {
		t.Fatal("missing raw request binding accepted")
	}
}
