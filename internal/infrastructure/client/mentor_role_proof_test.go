package client

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/example/ms-rbac-service/internal/domain"
)

const (
	mentorProofTestNow         = int64(1_800_000_000)
	mentorProofTestAdmin       = "00000000-0000-4000-8000-000000000a01"
	mentorProofTestTarget      = "00000000-0000-4000-8000-000000000b01"
	mentorProofTestApplication = "00000000-0000-4000-8000-000000000c01"
	mentorProofTestRequest     = "00000000-0000-4000-8000-000000000d01"
	mentorProofTestJTI         = "00000000-0000-4000-8000-000000000e01"
	mentorProofTestHeader      = `{"alg":"RS256","typ":"JWT"}`
)

func TestAuthMentorRoleProofVerifierAdmitsExactSignedBindings(t *testing.T) {
	key, verifier := mentorProofTestVerifier(t)
	for _, tc := range []struct {
		decision string
		revision uint64
	}{
		{domain.MentorRoleDecisionApprove, 2}, {domain.MentorRoleDecisionSuspend, 3}, {domain.MentorRoleDecisionSuspend, 4},
	} {
		t.Run(tc.decision+strconv.FormatUint(tc.revision, 10), func(t *testing.T) {
			claims := mentorProofTestClaims()
			claims["decision"] = tc.decision
			claims["application_revision"] = tc.revision
			mentorProofTestDigest(claims)
			token := signMentorProof(t, key, mentorProofTestHeader, marshalMentorProofClaims(t, claims))
			proof, err := verifier.VerifyMentorRoleProof(context.Background(), token)
			digest := sha256.Sum256([]byte(token))
			want := domain.MentorRoleCommand{
				Issuer: domain.MentorRoleProofIssuer, AdminID: mentorProofTestAdmin, TargetUserID: mentorProofTestTarget,
				ApplicationID: mentorProofTestApplication, ApplicationRevision: tc.revision,
				Decision: tc.decision, RequestID: mentorProofTestRequest, DecisionDigest: claims["decision_digest"].(string),
				Role: domain.MentorRole, Service: domain.MentorRoleService,
			}
			if err != nil || proof.Command != want || proof.JWTID != mentorProofTestJTI || proof.ProofDigest != hex.EncodeToString(digest[:]) || proof.IssuedAt != mentorProofTestNow || proof.ExpiresAt != mentorProofTestNow+30 {
				t.Fatalf("valid signed Mentor binding was not recovered exactly: %v", err)
			}
			second, err := verifier.VerifyMentorRoleProof(context.Background(), token)
			if err != nil || second != proof {
				t.Fatalf("fresh identical proof replay must remain cryptographically valid for idempotent admission: %v", err)
			}
		})
	}
	claims := mentorProofTestClaims()
	claims["iat"] = mentorProofTestNow + 5
	claims["exp"] = mentorProofTestNow + 35
	if _, err := verifier.VerifyMentorRoleProof(context.Background(), signMentorProof(t, key, mentorProofTestHeader, marshalMentorProofClaims(t, claims))); err != nil {
		t.Fatalf("exact five-second future skew must be admitted: %v", err)
	}
	verifier.now = func() time.Time { return time.Unix(domain.MentorRoleProofMaxTimestamp-30, 0) }
	claims["iat"] = domain.MentorRoleProofMaxTimestamp - 30
	claims["exp"] = domain.MentorRoleProofMaxTimestamp
	if _, err := verifier.VerifyMentorRoleProof(context.Background(), signMentorProof(t, key, mentorProofTestHeader, marshalMentorProofClaims(t, claims))); err != nil {
		t.Fatalf("exact positive safe-integer boundary must be admitted without overflow: %v", err)
	}
}

func TestAuthMentorRoleProofVerifierRejectsWrongAuthorityBindingsAndTime(t *testing.T) {
	key, verifier := mentorProofTestVerifier(t)
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"issuer", func(c map[string]any) { c["iss"] = "auth-service" }},
		{"audience", func(c map[string]any) { c["aud"] = "ms-go-rbac-knowledge-review" }},
		{"type", func(c map[string]any) { c["typ"] = "knowledge_graph_permission_check" }},
		{"purpose", func(c map[string]any) { c["purpose"] = "AUTH_RBAC_KNOWLEDGE_GRAPH_REVIEW_PERMISSION_V1" }},
		{"global role", func(c map[string]any) { c["role"] = "admin" }},
		{"global service", func(c map[string]any) { c["service"] = "core" }},
		{"subject nil", func(c map[string]any) { c["sub"] = "00000000-0000-0000-0000-000000000000" }},
		{"subject uppercase", func(c map[string]any) { c["sub"] = "00000000-0000-4000-8000-000000000A01" }},
		{"target nil", func(c map[string]any) { c["target_user_id"] = "00000000-0000-0000-0000-000000000000" }},
		{"target uppercase", func(c map[string]any) { c["target_user_id"] = "00000000-0000-4000-8000-000000000B01" }},
		{"application malformed", func(c map[string]any) { c["application_id"] = "bad" }},
		{"request malformed", func(c map[string]any) { c["request_id"] = "bad" }},
		{"jti malformed", func(c map[string]any) { c["jti"] = "bad" }},
		{"jti uppercase", func(c map[string]any) { c["jti"] = "00000000-0000-4000-8000-000000000E01" }},
		{"decision lower case", func(c map[string]any) { c["decision"] = "approve" }},
		{"reactivation decision", func(c map[string]any) { c["decision"] = "REACTIVATE" }},
		{"revision zero", func(c map[string]any) { c["application_revision"] = uint64(0); mentorProofTestDigest(c) }},
		{"local finalization revision", func(c map[string]any) { c["application_revision"] = uint64(3); mentorProofTestDigest(c) }},
		{"reactivation revision", func(c map[string]any) { c["application_revision"] = uint64(5); mentorProofTestDigest(c) }},
		{"suspend invalid revision", func(c map[string]any) { c["decision"] = "SUSPEND"; mentorProofTestDigest(c) }},
		{"digest mismatch", func(c map[string]any) { c["decision_digest"] = strings.Repeat("0", 64) }},
		{"digest uppercase", func(c map[string]any) { c["decision_digest"] = strings.ToUpper(c["decision_digest"].(string)) }},
		{"bound admin mismatch", func(c map[string]any) { c["sub"] = "00000000-0000-4000-8000-000000000a02" }},
		{"bound request mismatch", func(c map[string]any) { c["request_id"] = "00000000-0000-4000-8000-000000000d02" }},
		{"bound application mismatch", func(c map[string]any) { c["application_id"] = "00000000-0000-4000-8000-000000000c02" }},
		{"issued zero", func(c map[string]any) { c["iat"] = int64(0) }},
		{"issued negative", func(c map[string]any) { c["iat"] = int64(-1) }},
		{"future six seconds", func(c map[string]any) { c["iat"] = mentorProofTestNow + 6; c["exp"] = mentorProofTestNow + 36 }},
		{"expired exact", func(c map[string]any) { c["iat"] = mentorProofTestNow - 30; c["exp"] = mentorProofTestNow }},
		{"negative expires", func(c map[string]any) { c["exp"] = int64(-1) }},
		{"zero lifetime", func(c map[string]any) { c["exp"] = c["iat"] }},
		{"negative lifetime", func(c map[string]any) { c["exp"] = mentorProofTestNow - 1 }},
		{"overlong lifetime", func(c map[string]any) { c["exp"] = mentorProofTestNow + 31 }},
		{"unsafe issued integer", func(c map[string]any) {
			c["iat"] = domain.MentorRoleProofMaxTimestamp + 1
			c["exp"] = domain.MentorRoleProofMaxTimestamp + 2
		}},
		{"unsafe expires integer", func(c map[string]any) { c["exp"] = domain.MentorRoleProofMaxTimestamp + 1 }},
		{"max int expires", func(c map[string]any) { c["exp"] = int64(1<<63 - 1) }},
		{"overflow delta", func(c map[string]any) { c["iat"] = int64(-1 << 63); c["exp"] = int64(1<<63 - 1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := mentorProofTestClaims()
			tc.mutate(claims)
			assertMentorProofDenied(t, verifier, signMentorProof(t, key, mentorProofTestHeader, marshalMentorProofClaims(t, claims)))
		})
	}
	for _, now := range []int64{-1 << 63, 0, 1<<63 - 1} {
		verifier.now = func() time.Time { return time.Unix(now, 0) }
		assertMentorProofDenied(t, verifier, signMentorProof(t, key, mentorProofTestHeader, marshalMentorProofClaims(t, mentorProofTestClaims())))
	}
}

func TestAuthMentorRoleProofVerifierRejectsEveryMalformedClaimShape(t *testing.T) {
	key, verifier := mentorProofTestVerifier(t)
	for name := range mentorProofTestClaims() {
		t.Run(name, func(t *testing.T) {
			for _, malformed := range []string{"missing", "null", "case alias", "duplicate", "escaped duplicate", "mistyped"} {
				t.Run(malformed, func(t *testing.T) {
					claims := mentorProofTestClaims()
					var body []byte
					switch malformed {
					case "missing":
						delete(claims, name)
					case "null":
						claims[name] = nil
					case "case alias":
						claims[strings.ToUpper(name)] = claims[name]
						delete(claims, name)
					case "mistyped":
						claims[name] = true
					case "duplicate", "escaped duplicate":
						body = marshalMentorProofClaims(t, claims)
						quotedName, _ := json.Marshal(name)
						if malformed == "escaped duplicate" {
							quotedName = []byte(`"\u00` + strconv.FormatInt(int64(name[0]), 16) + name[1:] + `"`)
						}
						value, _ := json.Marshal(claims[name])
						body = []byte(strings.TrimSuffix(string(body), "}") + "," + string(quotedName) + ":" + string(value) + "}")
					}
					if body == nil {
						body = marshalMentorProofClaims(t, claims)
					}
					assertMentorProofDenied(t, verifier, signMentorProof(t, key, mentorProofTestHeader, body))
				})
			}
		})
	}
	body := string(marshalMentorProofClaims(t, mentorProofTestClaims()))
	for _, invalid := range []string{
		strings.TrimSuffix(body, "}") + `,"admin":true}`,
		body + `{}`,
		`[]`, `null`, `true`, `"string"`, "", `{`,
	} {
		assertMentorProofDenied(t, verifier, signMentorProof(t, key, mentorProofTestHeader, []byte(invalid)))
	}
	for _, name := range []string{"iat", "exp", "application_revision"} {
		for _, number := range []string{"2.0", "2e0", "2E0", `"2"`, "-1", "18446744073709551616"} {
			claims := mentorProofTestClaims()
			claims[name] = json.RawMessage(number)
			assertMentorProofDenied(t, verifier, signMentorProof(t, key, mentorProofTestHeader, marshalMentorProofClaims(t, claims)))
		}
	}
}

func TestAuthMentorRoleProofVerifierRejectsHeadersEncodingAndTampering(t *testing.T) {
	key, verifier := mentorProofTestVerifier(t)
	claims := marshalMentorProofClaims(t, mentorProofTestClaims())
	for _, header := range []string{
		`{"alg":"none","typ":"JWT"}`, `{"alg":"HS256","typ":"JWT"}`, `{"alg":"rs256","typ":"JWT"}`,
		`{"alg":"RS256","typ":"jwt"}`, `{"alg":"RS256","typ":"JWT","kid":"key"}`,
		`{"alg":"RS256","typ":"JWT","jku":"https://untrusted.invalid/key"}`,
		`{"alg":"RS256","typ":"JWT","jwk":{}}`, `{"alg":"RS256","typ":"JWT","crit":[]}`,
		`{"alg":"RS256","alg":"RS256","typ":"JWT"}`, `{"alg":"RS256","\u0061lg":"RS256","typ":"JWT"}`,
		`{"Alg":"RS256","typ":"JWT"}`, `{"alg":null,"typ":"JWT"}`, `{"alg":"RS256"}`, `{"alg":true,"typ":"JWT"}`, `[]`, `{}`, `null`, mentorProofTestHeader + `{}`,
	} {
		assertMentorProofDenied(t, verifier, signMentorProof(t, key, header, claims))
	}
	valid := signMentorProof(t, key, mentorProofTestHeader, claims)
	parts := strings.Split(valid, ".")
	for _, malformed := range []string{
		"", "x", valid + ".x", "." + parts[1] + "." + parts[2], parts[0] + ".." + parts[2], parts[0] + "." + parts[1] + ".",
		parts[0] + "=." + parts[1] + "." + parts[2], parts[0] + "." + parts[1] + "=." + parts[2], valid + "=",
		parts[0] + "\n." + parts[1] + "." + parts[2], " " + valid, valid + "\n", strings.Repeat("a", 8193),
		parts[0] + "." + parts[1] + ".a", parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(make([]byte, key.PublicKey.Size())),
		parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"payload":"tampered"}`)) + "." + parts[2],
		base64.RawURLEncoding.EncodeToString([]byte(`{ "alg":"RS256","typ":"JWT"}`)) + "." + parts[1] + "." + parts[2],
	} {
		assertMentorProofDenied(t, verifier, malformed)
	}
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	assertMentorProofDenied(t, verifier, signMentorProof(t, wrongKey, mentorProofTestHeader, claims))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if proof, err := verifier.VerifyMentorRoleProof(ctx, valid); !errors.Is(err, domain.ErrUnauthenticated) || proof != (domain.MentorRoleProof{}) {
		t.Fatal("cancelled admission must fail closed")
	}
}

func TestAuthMentorRoleProofVerifierRejectsUnavailableOrInvalidKeys(t *testing.T) {
	for _, verifier := range []*AuthMentorRoleProofVerifier{nil, {}} {
		if proof, err := verifier.VerifyMentorRoleProof(context.Background(), "ignored"); !errors.Is(err, domain.ErrAuthorityUnavailable) || proof != (domain.MentorRoleProof{}) {
			t.Fatal("unconfigured verifier must deny before parsing proof")
		}
	}
	unconfigured, err := NewAuthMentorRoleProofVerifier("")
	if err != nil {
		t.Fatal(err)
	}
	if proof, err := unconfigured.VerifyMentorRoleProof(context.Background(), "ignored"); !errors.Is(err, domain.ErrAuthorityUnavailable) || proof != (domain.MentorRoleProof{}) {
		t.Fatal("missing configuration must be unavailable")
	}
	key, _ := mentorProofTestVerifier(t)
	pkix, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pkixPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkix}))
	pkcs1PEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey)}))
	for _, encoded := range []string{pkixPEM, pkcs1PEM, "\n" + pkixPEM + "\n"} {
		v, err := NewAuthMentorRoleProofVerifier(encoded)
		if err != nil {
			t.Fatalf("supported RSA public key rejected: %v", err)
		}
		v.now = func() time.Time { return time.Unix(mentorProofTestNow, 0) }
		if _, err := v.VerifyMentorRoleProof(context.Background(), signMentorProof(t, key, mentorProofTestHeader, marshalMentorProofClaims(t, mentorProofTestClaims()))); err != nil {
			t.Fatalf("configured RSA public key failed: %v", err)
		}
	}
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecBytes, err := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, encoded := range []string{
		" ", "invalid", pkixPEM + pkixPEM, "junk" + pkixPEM, pkixPEM + "junk",
		string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&small.PublicKey)})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ecBytes})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkix})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Headers: map[string]string{"extra": "value"}, Bytes: pkix})),
	} {
		if _, err := NewAuthMentorRoleProofVerifier(encoded); err == nil {
			t.Fatal("invalid configured key was accepted")
		}
	}
}

func TestAuthMentorRoleProofVerifierRejectsNilOrMidAdmissionCancelledContext(t *testing.T) {
	key, verifier := mentorProofTestVerifier(t)
	token := signMentorProof(t, key, mentorProofTestHeader, marshalMentorProofClaims(t, mentorProofTestClaims()))
	t.Run("nil context", func(t *testing.T) {
		defer func() {
			if recover() != nil {
				t.Error("nil context must deny, not panic")
			}
		}()
		if proof, err := verifier.VerifyMentorRoleProof(nil, token); !errors.Is(err, domain.ErrUnauthenticated) || proof != (domain.MentorRoleProof{}) {
			t.Fatal("nil context must fail closed")
		}
	})
	t.Run("cancelled during admission", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		verifier.now = func() time.Time {
			cancel()
			return time.Unix(mentorProofTestNow, 0)
		}
		if proof, err := verifier.VerifyMentorRoleProof(ctx, token); !errors.Is(err, domain.ErrUnauthenticated) || proof != (domain.MentorRoleProof{}) {
			t.Fatal("mid-admission cancellation must not return authenticated claims")
		}
	})
}

func mentorProofTestVerifier(t *testing.T) (*rsa.PrivateKey, *AuthMentorRoleProofVerifier) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewAuthMentorRoleProofVerifier(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKey})))
	if err != nil {
		t.Fatal(err)
	}
	verifier.now = func() time.Time { return time.Unix(mentorProofTestNow, 0) }
	return key, verifier
}

func mentorProofTestClaims() map[string]any {
	claims := map[string]any{
		"iss": domain.MentorRoleProofIssuer, "aud": domain.MentorRoleProofAudience, "sub": mentorProofTestAdmin,
		"typ": domain.MentorRoleProofType, "purpose": domain.MentorRoleProofPurpose,
		"target_user_id": mentorProofTestTarget, "application_id": mentorProofTestApplication,
		"application_revision": uint64(2), "decision": domain.MentorRoleDecisionApprove, "request_id": mentorProofTestRequest,
		"role": domain.MentorRole, "service": domain.MentorRoleService, "jti": mentorProofTestJTI,
		"iat": mentorProofTestNow, "exp": mentorProofTestNow + 30,
	}
	mentorProofTestDigest(claims)
	return claims
}

func mentorProofTestDigest(claims map[string]any) {
	digest := sha256.Sum256([]byte(claims["decision"].(string) + "|" + claims["sub"].(string) + "|" + claims["application_id"].(string) + "|" + claims["request_id"].(string) + "|" + strconv.FormatUint(claims["application_revision"].(uint64)-1, 10)))
	claims["decision_digest"] = hex.EncodeToString(digest[:])
}

func marshalMentorProofClaims(t *testing.T, claims map[string]any) []byte {
	t.Helper()
	encoded, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func signMentorProof(t *testing.T, key *rsa.PrivateKey, header string, claims []byte) string {
	t.Helper()
	input := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func assertMentorProofDenied(t *testing.T, verifier *AuthMentorRoleProofVerifier, token string) {
	t.Helper()
	if proof, err := verifier.VerifyMentorRoleProof(context.Background(), token); !errors.Is(err, domain.ErrUnauthenticated) || proof != (domain.MentorRoleProof{}) {
		t.Fatalf("invalid proof must return only zero value and unauthenticated: %v", err)
	}
}
