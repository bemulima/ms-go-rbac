package client

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/example/ms-rbac-service/internal/domain"
)

func mcpStudentProofClaims(now int64) map[string]any {
	return map[string]any{
		"iss": "auth-service", "aud": domain.MCPStudentRoleProofAudience,
		"sub": reviewerProofTestSubject, "typ": domain.MCPStudentRoleProofType,
		"purpose": domain.MCPStudentRoleProofPurpose, "role": domain.MCPStudentRole,
		"jti": reviewerProofTestJTI, "iat": now,
		"exp": now + domain.MCPStudentRoleProofMaxAgeSeconds,
	}
}

func TestMCPStudentProofVerifierAcceptsOnlyDedicatedSignedAssertion(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: mustPKIXPublicKey(t, &key.PublicKey)})
	verifier, err := NewAuthMCPStudentRoleProofVerifier(string(publicPEM), "auth-service")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	verifier.now = func() time.Time { return now }
	valid := mcpStudentProofClaims(now.Unix())
	proof := signReviewerProof(t, key, `{"alg":"RS256","typ":"JWT"}`, marshalReviewerClaims(t, valid))
	identity, err := verifier.VerifyMCPStudentRoleProof(context.Background(), proof)
	if err != nil || identity.Subject != reviewerProofTestSubject || identity.JWTID != reviewerProofTestJTI {
		t.Fatalf("dedicated signed proof = (%+v, %v)", identity, err)
	}

	for _, tc := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"issuer", func(c map[string]any) { c["iss"] = "other" }},
		{"audience", func(c map[string]any) { c["aud"] = domain.ReviewerPermissionProofAudience }},
		{"purpose", func(c map[string]any) { c["purpose"] = domain.ReviewerPermissionProofPurpose }},
		{"type", func(c map[string]any) { c["typ"] = domain.ReviewerPermissionProofType }},
		{"role escalation", func(c map[string]any) { c["role"] = "admin" }},
		{"invalid subject", func(c map[string]any) { c["sub"] = "foreign-user" }},
		{"nil subject", func(c map[string]any) { c["sub"] = "00000000-0000-0000-0000-000000000000" }},
		{"uppercase jti", func(c map[string]any) { c["jti"] = "00000000-0000-4000-8000-00000000090A" }},
		{"expired", func(c map[string]any) { c["exp"] = now.Unix() }},
		{"future iat", func(c map[string]any) { c["iat"] = now.Unix() + domain.MCPStudentRoleProofFutureSkewSeconds + 1 }},
		{"too old", func(c map[string]any) { c["exp"] = now.Unix() + domain.MCPStudentRoleProofMaxAgeSeconds + 1 }},
		{"extra field", func(c map[string]any) { c["permission"] = "knowledge_graph.review" }},
		{"missing role", func(c map[string]any) { delete(c, "role") }},
	}{
		t.Run(tc.name, func(t *testing.T) {
			claims := mcpStudentProofClaims(now.Unix())
			tc.edit(claims)
			jwt := signReviewerProof(t, key, `{"alg":"RS256","typ":"JWT"}`, marshalReviewerClaims(t, claims))
			if got, err := verifier.VerifyMCPStudentRoleProof(context.Background(), jwt); err == nil || got.Subject != "" {
				t.Fatalf("unsafe proof accepted: %+v", got)
			}
		})
	}
	for _, header := range []string{`{"alg":"none","typ":"JWT"}`, `{"alg":"RS256","typ":"JWT","kid":"other"}`} {
		jwt := signReviewerProof(t, key, header, marshalReviewerClaims(t, valid))
		if _, err := verifier.VerifyMCPStudentRoleProof(context.Background(), jwt); err == nil {
			t.Fatal("unexpected JWT header accepted")
		}
	}
	duplicate := strings.TrimSuffix(string(marshalReviewerClaims(t, valid)), "}") + `,"role":"admin"}`
	if _, err := verifier.VerifyMCPStudentRoleProof(context.Background(), signReviewerProof(t, key, `{"alg":"RS256","typ":"JWT"}`, []byte(duplicate))); err == nil {
		t.Fatal("duplicate role claim accepted")
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.VerifyMCPStudentRoleProof(context.Background(), signReviewerProof(t, otherKey, `{"alg":"RS256","typ":"JWT"}`, marshalReviewerClaims(t, valid))); err == nil {
		t.Fatal("wrong Auth signature accepted")
	}
	if _, err := verifier.VerifyMCPStudentRoleProof(context.Background(), "anything"); err == nil {
		t.Fatal("unsigned proof accepted")
	}
}

func TestMCPStudentProofVerifierDisabledWithoutConfiguredKey(t *testing.T) {
	verifier, err := NewAuthMCPStudentRoleProofVerifier("", "auth-service")
	if err != nil {
		t.Fatal(err)
	}
	if proof, err := verifier.VerifyMCPStudentRoleProof(context.Background(), "any-token"); proof.Subject != "" || !errors.Is(err, domain.ErrAuthorityUnavailable) {
		t.Fatalf("missing key = (%+v, %v)", proof, err)
	}
	if _, err := NewAuthMCPStudentRoleProofVerifier("bad-pem", "auth-service"); err == nil {
		t.Fatal("bad public key accepted")
	}
	if _, err := NewAuthMCPStudentRoleProofVerifier("", ""); err == nil {
		t.Fatal("empty Auth issuer accepted")
	}
}
