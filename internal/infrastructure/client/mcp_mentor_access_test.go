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
	"strings"
	"testing"
	"time"

	"github.com/example/ms-rbac-service/internal/domain"
)

func mcpMentorCryptoKey(t *testing.T) (*rsa.PrivateKey, string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	private := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	public, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	return key, private, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}))
}
func mcpMentorSigned(t *testing.T, key *rsa.PrivateKey, body any) string {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	raw := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString(data)
	hash := sha256.Sum256([]byte(raw))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	return raw + "." + base64.RawURLEncoding.EncodeToString(signature)
}
func mcpMentorClaims(now time.Time) map[string]any {
	return map[string]any{"iss": "https://api.example.test/mentor", "aud": domain.MCPMentorProofAudience, "sub": "10000000-0000-4000-8000-000000000001", "persona": "MENTOR", "purpose": domain.MCPMentorProofPurpose, "scope": domain.MCPMentorProfileScope, "jti": "20000000-0000-4000-8000-000000000001", "iat": now.Unix(), "exp": now.Add(15 * time.Second).Unix()}
}
func TestMCPMentorSignedProofAndDecisionBindNonceDigestAndExpiry(t *testing.T) {
	authKey, _, authPublic := mcpMentorCryptoKey(t)
	_, rbacPrivate, _ := mcpMentorCryptoKey(t)
	authority, err := NewMCPMentorAuthority(authPublic, "https://api.example.test/mentor", rbacPrivate)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	authority.now = func() time.Time { return now }
	raw := mcpMentorSigned(t, authKey, mcpMentorClaims(now))
	proof, err := authority.VerifyMCPMentorProof(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, access := range []domain.MCPMentorAccess{{}, {Active: true}, {Active: true, Allowed: true}} {
		signed, err := authority.SignMCPMentorDecision(proof, access)
		if err != nil {
			t.Fatal(err)
		}
		parts := strings.Split(signed, ".")
		data, err := decodeJWTPart(parts[1])
		if err != nil {
			t.Fatal(err)
		}
		var claims map[string]any
		if json.Unmarshal(data, &claims) != nil {
			t.Fatal("invalid decision")
		}
		if len(claims) != 13 || claims["request_jti"] != proof.JWTID || claims["request_digest"] != proof.Digest || claims["aud"] != domain.MCPMentorDecisionAudience || claims["purpose"] != domain.MCPMentorDecisionPurpose || claims["scope"] != domain.MCPMentorProfileScope || claims["active"] != access.Active || claims["allowed"] != access.Allowed || int64(claims["exp"].(float64)) > proof.ExpiresAt {
			t.Fatal("decision lost authenticated binding")
		}
	}
	authority.now = func() time.Time { return now.Add(15 * time.Second) }
	if _, err := authority.SignMCPMentorDecision(proof, domain.MCPMentorAccess{Active: true, Allowed: true}); err == nil {
		t.Fatal("expired request signed after lookup")
	}
}
func TestMCPMentorProofRejectsPersonaScopeAndAuthoritySubstitution(t *testing.T) {
	authKey, _, authPublic := mcpMentorCryptoKey(t)
	otherKey, rbacPrivate, _ := mcpMentorCryptoKey(t)
	authority, err := NewMCPMentorAuthority(authPublic, "https://api.example.test/mentor", rbacPrivate)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	authority.now = func() time.Time { return now }
	for name, edit := range map[string]func(map[string]any){
		"Student persona": func(c map[string]any) { c["persona"] = "STUDENT" },
		"Student scope":   func(c map[string]any) { c["scope"] = "profile:read" },
		"mixed scope":     func(c map[string]any) { c["scope"] = "mentor:profile:read profile:read" },
		"role mutation":   func(c map[string]any) { c["purpose"] = domain.MentorRoleProofPurpose },
		"owner proof":     func(c map[string]any) { c["aud"] = "ms-go-mentor-mcp"; c["purpose"] = "MCP_MENTOR_APPROVAL_V1" },
		"extra role":      func(c map[string]any) { c["role"] = "admin" },
		"future issue":    func(c map[string]any) { c["iat"] = now.Add(time.Second).Unix() },
		"excess TTL":      func(c map[string]any) { c["exp"] = now.Add(16 * time.Second).Unix() },
		"expired":         func(c map[string]any) { c["exp"] = now.Unix() },
		"nil subject":     func(c map[string]any) { c["sub"] = nil },
	} {
		t.Run(name, func(t *testing.T) {
			claims := mcpMentorClaims(now)
			edit(claims)
			if _, err := authority.VerifyMCPMentorProof(context.Background(), mcpMentorSigned(t, authKey, claims)); err == nil {
				t.Fatal("invalid signed proof admitted")
			}
		})
	}
	if _, err := authority.VerifyMCPMentorProof(context.Background(), mcpMentorSigned(t, otherKey, mcpMentorClaims(now))); err == nil {
		t.Fatal("wrong key admitted")
	}
	for _, raw := range []string{`{"sub":"a","sub":"b"}`, `{"s\u0075b":"a"}`, `{"Sub":"a"}`, `{"sub":null}`, "{\"sub\":\"\xff\"}"} {
		var c struct {
			Subject string `json:"sub"`
		}
		if mcpMentorProofJSON([]byte(raw), []string{"sub"}, &c) == nil {
			t.Fatal("ambiguous JSON admitted")
		}
	}
}

func TestMCPMentorAuthorityRejectsSharedModuliAcrossPurposes(t *testing.T) {
	key, private, public := mcpMentorCryptoKey(t)
	_, otherPrivate, _ := mcpMentorCryptoKey(t)
	if _, err := NewMCPMentorAuthority(public, "https://api.example.test/mentor", private); err == nil {
		t.Fatal("request/decision signing authority reused")
	}
	alias := rsa.PublicKey{N: key.N, E: 3}
	der, _ := x509.MarshalPKIXPublicKey(&alias)
	aliasPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	if _, err := NewMCPMentorAuthority(public, "https://api.example.test/mentor", otherPrivate, aliasPEM); err == nil {
		t.Fatal("same modulus with different exponent crossed purpose fence")
	}
	if _, err := NewMCPMentorAuthority(public, "https://api.example.test/mentor", otherPrivate, otherPrivate); err == nil {
		t.Fatal("legacy decision private key reused")
	}
}

func TestMCPMentorOffersDecisionKeepsVerifiedRequestScope(t *testing.T) {
	authKey, _, authPublic := mcpMentorCryptoKey(t)
	_, rbacPrivate, _ := mcpMentorCryptoKey(t)
	authority, err := NewMCPMentorAuthority(authPublic, "https://api.example.test/mentor", rbacPrivate)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	authority.now = func() time.Time { return now }
	claims := mcpMentorClaims(now)
	claims["scope"] = domain.MCPMentorOffersScope
	proof, err := authority.VerifyMCPMentorProof(context.Background(), mcpMentorSigned(t, authKey, claims))
	if err != nil || proof.Scope != domain.MCPMentorOffersScope {
		t.Fatalf("offers request not admitted with exact scope: %v", err)
	}
	signed, err := authority.SignMCPMentorDecision(proof, domain.MCPMentorAccess{Active: true})
	if err != nil {
		t.Fatal(err)
	}
	body, err := decodeJWTPart(strings.Split(signed, ".")[1])
	if err != nil || json.Unmarshal(body, &claims) != nil || claims["scope"] != domain.MCPMentorOffersScope || claims["allowed"] != false {
		t.Fatal("denied offers decision lost exact scope")
	}
}
