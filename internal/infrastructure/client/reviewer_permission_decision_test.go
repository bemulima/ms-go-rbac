package client

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/example/ms-rbac-service/internal/domain"
)

func TestReviewerPermissionDecisionSignerBindsExactPermissionAndRequest(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	signer, err := NewReviewerPermissionDecisionSigner(string(privatePEM))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	signer.now = func() time.Time { return now }
	proof := domain.ReviewerPermissionProof{
		Subject: reviewerProofTestSubject, JWTID: reviewerProofTestJTI,
		Permission: domain.KnowledgeGraphReviewPermission,
	}
	const rawProof = "signed-auth-proof"
	token, err := signer.Sign(proof, rawProof, true)
	if err != nil {
		t.Fatal(err)
	}
	claims := verifyReviewerPermissionDecisionForTest(t, key, token)
	requestDigest := sha256.Sum256([]byte(rawProof))
	if claims["iss"] != domain.ReviewerPermissionDecisionIssuer ||
		claims["aud"] != domain.ReviewerPermissionDecisionAudience ||
		claims["sub"] != reviewerProofTestSubject || claims["typ"] != domain.ReviewerPermissionDecisionType ||
		claims["purpose"] != domain.ReviewerPermissionDecisionPurpose ||
		claims["permission"] != domain.KnowledgeGraphReviewPermission || claims["decision"] != "ALLOW" ||
		claims["request_jti"] != reviewerProofTestJTI || claims["request_digest"] != hex.EncodeToString(requestDigest[:]) {
		t.Fatalf("decision claims are not bound to the verified request: %#v", claims)
	}
	responseJTI, _ := claims["jti"].(string)
	if !domain.ValidPrincipalID(responseJTI) || responseJTI == proof.JWTID {
		t.Fatalf("response jti invalid or reused request jti: %q", responseJTI)
	}
	iat := int64(claims["iat"].(float64))
	exp := int64(claims["exp"].(float64))
	if exp-iat != domain.ReviewerPermissionDecisionTTLSeconds || exp-iat > domain.ReviewerPermissionDecisionMaxAgeSeconds {
		t.Fatalf("decision lifetime = %d seconds", exp-iat)
	}
	denied, err := signer.Sign(proof, rawProof, false)
	if err != nil || verifyReviewerPermissionDecisionForTest(t, key, denied)["decision"] != "DENY" {
		t.Fatalf("signed denial failed: err=%v", err)
	}
}

func TestReviewerPermissionDecisionSignerFailsClosedWithoutKeyOrValidBinding(t *testing.T) {
	if signer, err := NewReviewerPermissionDecisionSigner(""); signer != nil || err != nil {
		t.Fatalf("empty signer config = (%v, %v), want disabled", signer, err)
	}
	if _, err := NewReviewerPermissionDecisionSigner("not-a-pem"); err == nil {
		t.Fatal("malformed decision signing key was accepted")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	signer, err := NewReviewerPermissionDecisionSigner(string(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Sign(domain.ReviewerPermissionProof{}, "proof", true); err == nil {
		t.Fatal("signer accepted empty subject/JTI/permission binding")
	}
	if _, err := signer.Sign(domain.ReviewerPermissionProof{Subject: "00000000-0000-0000-0000-000000000000", JWTID: reviewerProofTestJTI, Permission: domain.KnowledgeGraphReviewPermission}, "proof", true); err == nil {
		t.Fatal("signer accepted nil subject")
	}
}

func verifyReviewerPermissionDecisionForTest(t *testing.T, key *rsa.PrivateKey, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("decision token has %d parts", len(parts))
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || string(headerBytes) != "{\"alg\":\"RS256\",\"typ\":\"JWT\"}" {
		t.Fatalf("invalid signed decision header %q: %v", headerBytes, err)
	}
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{}
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		t.Fatal(err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatalf("decision signature did not verify: %v", err)
	}
	return claims
}
