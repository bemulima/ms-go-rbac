package client

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/example/ms-rbac-service/internal/domain"
)

const reviewerProofTestSubject = "00000000-0000-4000-8000-000000000901"
const reviewerProofTestJTI = "00000000-0000-4000-8000-000000000902"

func TestAuthReviewerPermissionProofVerifierAcceptsOnlyBoundedAuthProof(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: mustPKIXPublicKey(t, &privateKey.PublicKey)})
	verifier, err := NewAuthReviewerPermissionProofVerifier(string(publicKey), "auth-service")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	verifier.now = func() time.Time { return now }

	valid := reviewerProofClaims(now.Unix())
	proof := signReviewerProof(t, privateKey, `{"alg":"RS256","typ":"JWT"}`, marshalReviewerClaims(t, valid))
	verified, err := verifier.VerifyReviewerPermissionProof(context.Background(), proof)
	if err != nil || verified.Subject != reviewerProofTestSubject || verified.JWTID != reviewerProofTestJTI ||
		verified.Permission != domain.KnowledgeGraphReviewPermission {
		t.Fatalf("valid proof = (%+v, %v), want subject/JTI/permission binding", verified, err)
	}

	cases := []struct {
		name   string
		change func(map[string]any)
	}{
		{"issuer", func(c map[string]any) { c["iss"] = "other-auth" }},
		{"audience", func(c map[string]any) { c["aud"] = "other-service" }},
		{"subject", func(c map[string]any) { c["sub"] = "not-a-uuid" }},
		{"proof type", func(c map[string]any) { c["typ"] = "knowledge_graph_reviewer" }},
		{"purpose", func(c map[string]any) { c["purpose"] = "other-purpose" }},
		{"permission", func(c map[string]any) { c["permission"] = "knowledge_graph.publish" }},
		{"jti", func(c map[string]any) { c["jti"] = "not-a-uuid" }},
		{"future issued at", func(c map[string]any) { c["iat"] = now.Unix() + domain.ReviewerPermissionProofFutureSkewSeconds + 1 }},
		{"expired", func(c map[string]any) { c["exp"] = now.Unix() }},
		{"nonpositive issued at", func(c map[string]any) { c["iat"] = int64(0) }},
		{"nonpositive lifetime", func(c map[string]any) { c["exp"] = c["iat"] }},
		{"long lifetime", func(c map[string]any) { c["exp"] = c["iat"].(int64) + domain.ReviewerPermissionProofMaxAgeSeconds + 1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := reviewerProofClaims(now.Unix())
			tc.change(claims)
			proof := signReviewerProof(t, privateKey, `{"alg":"RS256","typ":"JWT"}`, marshalReviewerClaims(t, claims))
			if verified, err := verifier.VerifyReviewerPermissionProof(context.Background(), proof); err == nil || verified.Subject != "" {
				t.Fatalf("invalid proof accepted with claims %+v", verified)
			}
		})
	}

	for _, header := range []string{
		`{"alg":"HS256","typ":"JWT"}`,
		`{"alg":"RS256","typ":"JWT","kid":"unconfigured"}`,
		`{"alg":"RS256","alg":"none","typ":"JWT"}`,
	} {
		t.Run("header "+header, func(t *testing.T) {
			proof := signReviewerProof(t, privateKey, header, marshalReviewerClaims(t, valid))
			if _, err := verifier.VerifyReviewerPermissionProof(context.Background(), proof); err == nil {
				t.Fatal("unaccepted header was accepted")
			}
		})
	}

	duplicateClaim := `{"iss":"auth-service","aud":"ms-go-rbac-knowledge-review","sub":"` + reviewerProofTestSubject + `","typ":"knowledge_graph_permission_check","purpose":"AUTH_RBAC_KNOWLEDGE_GRAPH_REVIEW_PERMISSION_V1","permission":"knowledge_graph.review","permission":"knowledge_graph.publish","jti":"` + reviewerProofTestJTI + `","iat":1800000000,"exp":1800000030}`
	if _, err := verifier.VerifyReviewerPermissionProof(context.Background(), signReviewerProof(t, privateKey, `{"alg":"RS256","typ":"JWT"}`, []byte(duplicateClaim))); err == nil {
		t.Fatal("duplicate permission claim was accepted")
	}
	unknownClaim := strings.TrimSuffix(string(marshalReviewerClaims(t, valid)), "}") + `,"admin":true}`
	if _, err := verifier.VerifyReviewerPermissionProof(context.Background(), signReviewerProof(t, privateKey, `{"alg":"RS256","typ":"JWT"}`, []byte(unknownClaim))); err == nil {
		t.Fatal("unknown claim was accepted")
	}

	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.VerifyReviewerPermissionProof(context.Background(), signReviewerProof(t, wrongKey, `{"alg":"RS256","typ":"JWT"}`, marshalReviewerClaims(t, valid))); err == nil {
		t.Fatal("proof signed by an untrusted key was accepted")
	}
}

func TestAuthReviewerPermissionProofVerifierFailsClosedWhenAuthorityUnavailable(t *testing.T) {
	verifier, err := NewAuthReviewerPermissionProofVerifier("", "auth-service")
	if err != nil {
		t.Fatal(err)
	}
	if proof, err := verifier.VerifyReviewerPermissionProof(context.Background(), "any-token"); proof.Subject != "" || !errors.Is(err, domain.ErrAuthorityUnavailable) {
		t.Fatalf("missing public key = (%+v, %v), want unavailable", proof, err)
	}
	if _, err := NewAuthReviewerPermissionProofVerifier("not-a-pem", "auth-service"); err == nil {
		t.Fatal("malformed configured public key did not fail composition")
	}
	if _, err := NewAuthReviewerPermissionProofVerifier("", ""); err == nil {
		t.Fatal("missing issuer did not fail composition")
	}
}

func reviewerProofClaims(now int64) map[string]any {
	return map[string]any{
		"iss":        "auth-service",
		"aud":        domain.ReviewerPermissionProofAudience,
		"sub":        reviewerProofTestSubject,
		"typ":        domain.ReviewerPermissionProofType,
		"purpose":    domain.ReviewerPermissionProofPurpose,
		"permission": domain.KnowledgeGraphReviewPermission,
		"jti":        reviewerProofTestJTI,
		"iat":        now,
		"exp":        now + domain.ReviewerPermissionProofMaxAgeSeconds,
	}
}

func marshalReviewerClaims(t *testing.T, claims map[string]any) []byte {
	t.Helper()
	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func signReviewerProof(t *testing.T, key *rsa.PrivateKey, header string, claims []byte) string {
	t.Helper()
	headerPart := base64.RawURLEncoding.EncodeToString([]byte(header))
	claimsPart := base64.RawURLEncoding.EncodeToString(claims)
	signed := headerPart + "." + claimsPart
	digest := sha256.Sum256([]byte(signed))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%s.%s", signed, base64.RawURLEncoding.EncodeToString(signature))
}

func mustPKIXPublicKey(t *testing.T, key *rsa.PublicKey) []byte {
	t.Helper()
	encoded, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
