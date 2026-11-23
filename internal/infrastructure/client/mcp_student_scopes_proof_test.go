package client

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/example/ms-rbac-service/internal/domain"
)

func validMCPStudentScopeClaims(now int64) map[string]any {
	return map[string]any{
		"iss": "auth-service", "aud": domain.MCPStudentScopeProofAudience,
		"sub": reviewerProofTestSubject, "typ": domain.MCPStudentScopeProofType,
		"purpose": domain.MCPStudentScopeProofPurpose,
		"scopes":  []string{domain.MCPStudentCoursesReadScope, domain.MCPStudentProfileReadScope, domain.MCPStudentTasksReadScope},
		"jti":     reviewerProofTestJTI, "iat": now,
		"exp": now + domain.MCPStudentScopeProofMaxAgeSeconds,
	}
}

func TestMCPStudentScopeProofRequiresExactAuthSignedPilotScopeSet(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	public := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: mustPKIXPublicKey(t, &key.PublicKey)})
	verifier, err := NewAuthMCPStudentScopeProofVerifier(string(public), "auth-service")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	verifier.now = func() time.Time { return now }
	valid := validMCPStudentScopeClaims(now.Unix())
	raw := signReviewerProof(t, key, `{"alg":"RS256","typ":"JWT"}`, marshalReviewerClaims(t, valid))
	proof, err := verifier.VerifyMCPStudentScopeProof(context.Background(), raw)
	want := []string{domain.MCPStudentCoursesReadScope, domain.MCPStudentProfileReadScope, domain.MCPStudentTasksReadScope}
	digest := sha256.Sum256([]byte(raw))
	if err != nil || proof.Subject != reviewerProofTestSubject || proof.JWTID != reviewerProofTestJTI ||
		!reflect.DeepEqual(proof.Requested, want) || proof.ProofDigest != hex.EncodeToString(digest[:]) {
		t.Fatalf("signed scope request: %+v err=%v", proof, err)
	}

	for _, tc := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"issuer", func(c map[string]any) { c["iss"] = "not-auth" }},
		{"audience", func(c map[string]any) { c["aud"] = domain.MCPStudentRoleProofAudience }},
		{"purpose", func(c map[string]any) { c["purpose"] = domain.MCPStudentRoleProofPurpose }},
		{"type", func(c map[string]any) { c["typ"] = domain.MCPStudentRoleProofType }},
		{"role claim forbidden", func(c map[string]any) { c["role"] = "student" }},
		{"reviewer permission forbidden", func(c map[string]any) { c["permission"] = domain.KnowledgeGraphReviewPermission }},
		{"wrong subject", func(c map[string]any) { c["sub"] = "foreign-user" }},
		{"nil UUID", func(c map[string]any) { c["sub"] = "00000000-0000-0000-0000-000000000000" }},
		{"uppercase subject", func(c map[string]any) { c["sub"] = "00000000-0000-4000-8000-00000000090A" }},
		{"uppercase jti", func(c map[string]any) { c["jti"] = "00000000-0000-4000-8000-00000000090A" }},
		{"expired", func(c map[string]any) { c["exp"] = now.Unix() }},
		{"future iat", func(c map[string]any) { c["iat"] = now.Unix() + domain.MCPStudentScopeProofFutureSkewSeconds + 1 }},
		{"overlong", func(c map[string]any) { c["exp"] = now.Unix() + domain.MCPStudentScopeProofMaxAgeSeconds + 1 }},
		{"missing scopes", func(c map[string]any) { delete(c, "scopes") }},
		{"null scopes", func(c map[string]any) { c["scopes"] = nil }},
		{"empty scopes", func(c map[string]any) { c["scopes"] = []string{} }},
		{"duplicate scopes", func(c map[string]any) { c["scopes"] = []string{"profile:read", "profile:read"} }},
		{"unsorted scopes", func(c map[string]any) { c["scopes"] = []string{"tasks:read", "profile:read"} }},
		{"write scope", func(c map[string]any) { c["scopes"] = []string{"tasks:write"} }},
		{"unknown scope", func(c map[string]any) { c["scopes"] = []string{"teacher:ask"} }},
		{"scope case", func(c map[string]any) { c["scopes"] = []string{"Profile:read"} }},
		{"too many", func(c map[string]any) {
			c["scopes"] = []string{"courses:read", "profile:read", "tasks:read", "write:read"}
		}},
		{"scope wrong type", func(c map[string]any) { c["scopes"] = []any{12} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := validMCPStudentScopeClaims(now.Unix())
			tc.edit(claims)
			candidate := signReviewerProof(t, key, `{"alg":"RS256","typ":"JWT"}`, marshalReviewerClaims(t, claims))
			got, err := verifier.VerifyMCPStudentScopeProof(context.Background(), candidate)
			if err == nil || got.Subject != "" || len(got.Requested) != 0 {
				t.Fatalf("malformed/unauthorized scope request accepted: %+v err=%v", got, err)
			}
		})
	}
	for _, header := range []string{`{"alg":"none","typ":"JWT"}`, `{"alg":"RS256","typ":"JWT","kid":"other"}`} {
		candidate := signReviewerProof(t, key, header, marshalReviewerClaims(t, valid))
		if _, err := verifier.VerifyMCPStudentScopeProof(context.Background(), candidate); err == nil {
			t.Fatal("non-exact scope proof header accepted")
		}
	}
	duplicate := strings.TrimSuffix(string(marshalReviewerClaims(t, valid)), "}") + `,"scopes":["tasks:write"]}`
	if _, err := verifier.VerifyMCPStudentScopeProof(context.Background(), signReviewerProof(t, key, `{"alg":"RS256","typ":"JWT"}`, []byte(duplicate))); err == nil {
		t.Fatal("duplicate scopes claim accepted")
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.VerifyMCPStudentScopeProof(context.Background(), signReviewerProof(t, otherKey, `{"alg":"RS256","typ":"JWT"}`, marshalReviewerClaims(t, valid))); err == nil {
		t.Fatal("wrong signer accepted")
	}
	if _, err := verifier.VerifyMCPStudentScopeProof(context.Background(), "unsigned-scopes"); err == nil {
		t.Fatal("unsigned scope request accepted")
	}
}

func TestMCPStudentScopeProofFailsClosedWithoutAuthority(t *testing.T) {
	verifier, err := NewAuthMCPStudentScopeProofVerifier("", "auth-service")
	if err != nil {
		t.Fatal(err)
	}
	if proof, err := verifier.VerifyMCPStudentScopeProof(context.Background(), "proof"); proof.Subject != "" || !errors.Is(err, domain.ErrAuthorityUnavailable) {
		t.Fatalf("missing verification key accepted: %+v %v", proof, err)
	}
	if _, err := NewAuthMCPStudentScopeProofVerifier("bad-pem", "auth-service"); err == nil {
		t.Fatal("malformed public key accepted")
	}
	if _, err := NewAuthMCPStudentScopeProofVerifier("", ""); err == nil {
		t.Fatal("empty Auth issuer accepted")
	}
	var missing *AuthMCPStudentScopeProofVerifier
	if proof, err := missing.VerifyMCPStudentScopeProof(context.Background(), "proof"); proof.Subject != "" || !errors.Is(err, domain.ErrAuthorityUnavailable) {
		t.Fatalf("missing verifier accepted: %+v %v", proof, err)
	}
	var missingContext context.Context
	if proof, err := verifier.VerifyMCPStudentScopeProof(missingContext, "proof"); proof.Subject != "" || !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("nil context accepted: %+v %v", proof, err)
	}
}
