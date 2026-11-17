package client

import (
	"context"
	"crypto"
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

const mentorAdminTestNow int64 = 1800000000
const mentorAdminTestActor = "00000000-0000-4000-8000-000000000a01"
const mentorAdminTestJTI = "00000000-0000-4000-8000-000000000e01"

func TestMentorAdminLookupVerifierRecoversOnlyExactSignedRequest(t *testing.T) {
	key, verifier, _ := mentorAdminCryptoFixture(t)
	claims := mentorAdminLookupTestClaims()
	token := signMentorProof(t, key, mentorProofTestHeader, marshalMentorProofClaims(t, claims))
	proof, err := verifier.VerifyMentorAdminLookupProof(context.Background(), domain.MentorCanonicalAdminSubject, token)
	digest := sha256.Sum256([]byte(token))
	want := domain.MentorAdminLookupProof{ActorID: mentorAdminTestActor, Subject: domain.MentorCanonicalAdminSubject, JWTID: mentorAdminTestJTI, ProofDigest: hex.EncodeToString(digest[:]), IssuedAt: mentorAdminTestNow, ExpiresAt: mentorAdminTestNow + 30}
	if err != nil || proof != want {
		t.Fatalf("valid dedicated lookup proof rejected: %v", err)
	}
	assertMentorAdminLookupDenied(t, verifier, domain.MentorCanonicalAdminSubject+".other", token)
	verifier.now = func() time.Time { return time.Unix(mentorAdminTestNow+30, 0) }
	assertMentorAdminLookupDenied(t, verifier, domain.MentorCanonicalAdminSubject, token)
}

func TestMentorAdminLookupVerifierRejectsEveryClaimShapeAndBinding(t *testing.T) {
	key, verifier, _ := mentorAdminCryptoFixture(t)
	for field := range mentorAdminLookupTestClaims() {
		t.Run(field, func(t *testing.T) {
			for _, shape := range []string{"missing", "null", "mistyped", "case alias", "duplicate", "escaped duplicate"} {
				t.Run(shape, func(t *testing.T) {
					claims := mentorAdminLookupTestClaims()
					var encoded []byte
					switch shape {
					case "missing":
						delete(claims, field)
					case "null":
						claims[field] = nil
					case "mistyped":
						claims[field] = true
					case "case alias":
						claims[strings.ToUpper(field)] = claims[field]
						delete(claims, field)
					default:
						quoted, _ := json.Marshal(field)
						value, _ := json.Marshal(claims[field])
						if shape == "escaped duplicate" {
							quoted = []byte(`"\u00` + strconv.FormatInt(int64(field[0]), 16) + field[1:] + `"`)
						}
						encoded = []byte(strings.TrimSuffix(string(marshalMentorProofClaims(t, claims)), "}") + "," + string(quoted) + ":" + string(value) + "}")
					}
					if encoded == nil {
						encoded = marshalMentorProofClaims(t, claims)
					}
					assertMentorAdminLookupDenied(t, verifier, domain.MentorCanonicalAdminSubject, signMentorProof(t, key, mentorProofTestHeader, encoded))
				})
			}
		})
	}
	for _, tc := range []struct {
		field string
		value any
	}{
		{"iss", "other"}, {"aud", domain.MentorRoleProofAudience}, {"typ", domain.MentorRoleProofType}, {"purpose", domain.MentorRoleProofPurpose},
		{"subject", "mentor.confirmCommittedRoleIntent.v1"}, {"sub", "bad"}, {"sub", "00000000-0000-0000-0000-000000000000"}, {"sub", "00000000-0000-4000-8000-000000000A01"}, {"jti", "bad"},
		{"iat", int64(0)}, {"iat", int64(-1)}, {"iat", mentorAdminTestNow + 6}, {"exp", mentorAdminTestNow}, {"exp", mentorAdminTestNow + 31}, {"exp", int64(1<<63 - 1)},
		{"iat", domain.MentorRoleProofMaxTimestamp + 1}, {"exp", domain.MentorRoleProofMaxTimestamp + 1}, {"role", "admin"},
	} {
		claims := mentorAdminLookupTestClaims()
		claims[tc.field] = tc.value
		assertMentorAdminLookupDenied(t, verifier, domain.MentorCanonicalAdminSubject, signMentorProof(t, key, mentorProofTestHeader, marshalMentorProofClaims(t, claims)))
	}
	for _, field := range []string{"iat", "exp"} {
		for _, value := range []string{"1800000000.0", "1800000000e0", `"1800000000"`, "18446744073709551616"} {
			claims := mentorAdminLookupTestClaims()
			claims[field] = json.RawMessage(value)
			assertMentorAdminLookupDenied(t, verifier, domain.MentorCanonicalAdminSubject, signMentorProof(t, key, mentorProofTestHeader, marshalMentorProofClaims(t, claims)))
		}
	}
	for _, raw := range []string{`[]`, `null`, `{}`, string(marshalMentorProofClaims(t, mentorAdminLookupTestClaims())) + `{}`} {
		assertMentorAdminLookupDenied(t, verifier, domain.MentorCanonicalAdminSubject, signMentorProof(t, key, mentorProofTestHeader, []byte(raw)))
	}
}

func TestMentorAdminLookupVerifierRejectsWrongKeysEncodingAndCancellation(t *testing.T) {
	key, verifier, _ := mentorAdminCryptoFixture(t)
	body := marshalMentorProofClaims(t, mentorAdminLookupTestClaims())
	for _, header := range []string{`{"alg":"none","typ":"JWT"}`, `{"alg":"HS256","typ":"JWT"}`, `{"alg":"RS256","typ":"JWT","kid":"other"}`, `{"alg":"RS256","alg":"RS256","typ":"JWT"}`, `{"alg":"RS256","\u0061lg":"RS256","typ":"JWT"}`, `{"Alg":"RS256","typ":"JWT"}`, `{"alg":null,"typ":"JWT"}`, `{"alg":"RS256"}`, mentorProofTestHeader + `{}`} {
		assertMentorAdminLookupDenied(t, verifier, domain.MentorCanonicalAdminSubject, signMentorProof(t, key, header, body))
	}
	valid := signMentorProof(t, key, mentorProofTestHeader, body)
	parts := strings.Split(valid, ".")
	for _, token := range []string{"", valid + "=", valid + ".x", parts[0] + "\n." + parts[1] + "." + parts[2], parts[0] + "." + parts[1] + "=." + parts[2], parts[0] + "." + parts[1] + ".a", strings.Repeat("a", 8193), parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{}`)) + "." + parts[2]} {
		assertMentorAdminLookupDenied(t, verifier, domain.MentorCanonicalAdminSubject, token)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	assertMentorAdminLookupDenied(t, verifier, domain.MentorCanonicalAdminSubject, signMentorProof(t, other, mentorProofTestHeader, body))
	for _, ctx := range []context.Context{nil, mentorAdminCancelledContext()} {
		if proof, err := verifier.VerifyMentorAdminLookupProof(ctx, domain.MentorCanonicalAdminSubject, valid); !errors.Is(err, domain.ErrUnauthenticated) || proof != (domain.MentorAdminLookupProof{}) {
			t.Fatal("invalid context did not deny")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	verifier.now = func() time.Time { cancel(); return time.Unix(mentorAdminTestNow, 0) }
	if proof, err := verifier.VerifyMentorAdminLookupProof(ctx, domain.MentorCanonicalAdminSubject, valid); !errors.Is(err, domain.ErrUnauthenticated) || proof != (domain.MentorAdminLookupProof{}) {
		t.Fatal("mid-verification cancellation did not deny")
	}
}

func TestMentorCanonicalAdminDecisionSignerBindsFreshNonceDigestAndExpiry(t *testing.T) {
	key, verifier, signer := mentorAdminCryptoFixture(t)
	request := signMentorProof(t, key, mentorProofTestHeader, marshalMentorProofClaims(t, mentorAdminLookupTestClaims()))
	proof, err := verifier.VerifyMentorAdminLookupProof(context.Background(), domain.MentorCanonicalAdminSubject, request)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, allowed := range []bool{true, false, true} {
		token, err := signer.Sign(context.Background(), proof, allowed)
		if err != nil || token == "" {
			t.Fatalf("valid decision was not signed: %v", err)
		}
		claims := verifyMentorAdminDecision(t, &key.PublicKey, token)
		decision := "DENY"
		if allowed {
			decision = "ALLOW"
		}
		if len(claims) != 12 || claims["iss"] != domain.MentorAdminDecisionIssuer || claims["aud"] != domain.MentorAdminDecisionAudience || claims["typ"] != domain.MentorAdminDecisionType || claims["purpose"] != domain.MentorAdminDecisionPurpose || claims["sub"] != proof.ActorID || claims["subject"] != proof.Subject || claims["request_jti"] != proof.JWTID || claims["request_digest"] != proof.ProofDigest || claims["decision"] != decision || claims["iat"] != float64(mentorAdminTestNow) || claims["exp"] != float64(mentorAdminTestNow+15) {
			t.Fatal("decision changed fixed claims, nonce, original-byte digest or TTL")
		}
		jti, ok := claims["jti"].(string)
		if !ok || !domain.ValidPrincipalID(jti) || seen[jti] || jti == proof.JWTID {
			t.Fatal("response nonce was not fresh canonical UUID")
		}
		seen[jti] = true
	}
	signer.now = func() time.Time { return time.Unix(mentorAdminTestNow+25, 0) }
	token, err := signer.Sign(context.Background(), proof, true)
	if err != nil {
		t.Fatal(err)
	}
	if verifyMentorAdminDecision(t, &key.PublicKey, token)["exp"] != float64(proof.ExpiresAt) {
		t.Fatal("response expiry escaped original request expiry")
	}
	signer.now = func() time.Time { return time.Unix(proof.ExpiresAt, 0) }
	if token, err := signer.Sign(context.Background(), proof, true); err == nil || token != "" {
		t.Fatal("expired original request was signed")
	}
}

func TestMentorAdminCryptoConstructorsAndSignerFailClosed(t *testing.T) {
	key, verifier, signer := mentorAdminCryptoFixture(t)
	request := signMentorProof(t, key, mentorProofTestHeader, marshalMentorProofClaims(t, mentorAdminLookupTestClaims()))
	proof, err := verifier.VerifyMentorAdminLookupProof(context.Background(), domain.MentorCanonicalAdminSubject, request)
	if err != nil {
		t.Fatal(err)
	}
	for _, ctx := range []context.Context{nil, mentorAdminCancelledContext()} {
		if token, err := signer.Sign(ctx, proof, true); err == nil || token != "" {
			t.Fatal("invalid signing context accepted")
		}
	}
	for _, mutate := range []func(*domain.MentorAdminLookupProof){
		func(p *domain.MentorAdminLookupProof) { p.ActorID = "bad" }, func(p *domain.MentorAdminLookupProof) { p.Subject = "rbac.checkRole" }, func(p *domain.MentorAdminLookupProof) { p.JWTID = "bad" }, func(p *domain.MentorAdminLookupProof) { p.ProofDigest = "bad" }, func(p *domain.MentorAdminLookupProof) { p.ProofDigest = strings.Repeat("A", 64) }, func(p *domain.MentorAdminLookupProof) { p.IssuedAt = 0 }, func(p *domain.MentorAdminLookupProof) { p.ExpiresAt = p.IssuedAt + 31 },
	} {
		changed := proof
		mutate(&changed)
		if token, err := signer.Sign(context.Background(), changed, true); err == nil || token != "" {
			t.Fatal("invalid recovered proof was signed")
		}
	}
	for _, v := range []*AuthMentorAdminLookupProofVerifier{nil, {}} {
		if recovered, err := v.VerifyMentorAdminLookupProof(context.Background(), domain.MentorCanonicalAdminSubject, request); !errors.Is(err, domain.ErrAuthorityUnavailable) || recovered != (domain.MentorAdminLookupProof{}) {
			t.Fatal("unconfigured lookup verifier was not unavailable")
		}
	}
	for _, s := range []*MentorCanonicalAdminDecisionSigner{nil, {}} {
		if token, err := s.Sign(context.Background(), proof, true); err == nil || token != "" {
			t.Fatal("unconfigured signer returned decision")
		}
	}
	blankVerifier, err := NewAuthMentorAdminLookupProofVerifier("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = blankVerifier.VerifyMentorAdminLookupProof(context.Background(), domain.MentorCanonicalAdminSubject, request); !errors.Is(err, domain.ErrAuthorityUnavailable) {
		t.Fatal("missing public key was not unavailable")
	}
	blankSigner, err := NewMentorCanonicalAdminDecisionSigner("")
	if err != nil {
		t.Fatal(err)
	}
	if token, err := blankSigner.Sign(context.Background(), proof, true); err == nil || token != "" {
		t.Fatal("missing private key returned decision")
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}))
	privatePEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	for _, encoded := range []string{" ", "invalid", "junk" + publicPEM, publicPEM + publicPEM, privatePEM} {
		if _, err := NewAuthMentorAdminLookupProofVerifier(encoded); err == nil {
			t.Fatal("invalid public key configuration accepted")
		}
	}
	for _, encoded := range []string{" ", "invalid", "junk" + privatePEM, privatePEM + privatePEM, publicPEM} {
		if _, err := NewMentorCanonicalAdminDecisionSigner(encoded); err == nil {
			t.Fatal("invalid private key configuration accepted")
		}
	}
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewAuthMentorAdminLookupProofVerifier(string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&small.PublicKey)}))); err == nil {
		t.Fatal("weak lookup key accepted")
	}
	if _, err := NewMentorCanonicalAdminDecisionSigner(string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(small)}))); err == nil {
		t.Fatal("weak reply key accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signer.now = func() time.Time { cancel(); return time.Unix(mentorAdminTestNow, 0) }
	if token, err := signer.Sign(ctx, proof, true); err == nil || token != "" {
		t.Fatal("mid-signing cancellation accepted")
	}
}

func TestMentorAdminLookupExactTimeSizeAndSigningCompletionBoundaries(t *testing.T) {
	key, verifier, signer := mentorAdminCryptoFixture(t)
	claims := mentorAdminLookupTestClaims()
	claims["iat"], claims["exp"] = mentorAdminTestNow+5, mentorAdminTestNow+35
	request := signMentorProof(t, key, mentorProofTestHeader, marshalMentorProofClaims(t, claims))
	if _, err := verifier.VerifyMentorAdminLookupProof(context.Background(), domain.MentorCanonicalAdminSubject, request); err != nil {
		t.Fatal("exact future-skew boundary rejected")
	}
	claims = mentorAdminLookupTestClaims()
	body := marshalMentorProofClaims(t, claims)
	headerSize := len(base64.RawURLEncoding.EncodeToString([]byte(mentorProofTestHeader)))
	signatureSize := base64.RawURLEncoding.EncodedLen(key.PublicKey.Size())
	payloadSize := (domain.MentorAdminLookupMaxTokenBytes - headerSize - signatureSize - 2) * 3 / 4
	padded := append(append([]byte{}, body...), []byte(strings.Repeat(" ", payloadSize-len(body)))...)
	request = signMentorProof(t, key, mentorProofTestHeader, padded)
	if len(request) != domain.MentorAdminLookupMaxTokenBytes {
		t.Fatal("boundary fixture does not reach exact token limit")
	}
	proof, err := verifier.VerifyMentorAdminLookupProof(context.Background(), domain.MentorCanonicalAdminSubject, request)
	if err != nil {
		t.Fatal("exact token size boundary rejected")
	}
	assertMentorAdminLookupDenied(t, verifier, domain.MentorCanonicalAdminSubject, signMentorProof(t, key, mentorProofTestHeader, append(padded, ' ')))
	clockCalls := 0
	signer.now = func() time.Time {
		clockCalls++
		if clockCalls == 1 {
			return time.Unix(mentorAdminTestNow, 0)
		}
		return time.Unix(proof.ExpiresAt, 0)
	}
	if token, err := signer.Sign(context.Background(), proof, true); err == nil || token != "" {
		t.Fatal("request expired during signing still produced a confirmation")
	}
	claims["iat"], claims["exp"] = domain.MentorAdminLookupMaxTimestamp-30, domain.MentorAdminLookupMaxTimestamp
	request = signMentorProof(t, key, mentorProofTestHeader, marshalMentorProofClaims(t, claims))
	verifier.now = func() time.Time { return time.Unix(domain.MentorAdminLookupMaxTimestamp-30, 0) }
	proof, err = verifier.VerifyMentorAdminLookupProof(context.Background(), domain.MentorCanonicalAdminSubject, request)
	if err != nil {
		t.Fatal("exact maximum safe timestamp boundary rejected")
	}
	signer.now = func() time.Time { return time.Unix(domain.MentorAdminLookupMaxTimestamp-5, 0) }
	token, err := signer.Sign(context.Background(), proof, true)
	if err != nil || verifyMentorAdminDecision(t, &key.PublicKey, token)["exp"] != float64(domain.MentorAdminLookupMaxTimestamp) {
		t.Fatal("reply expiry cap overflowed safe integer boundary")
	}
	for _, now := range []int64{0, -1, 1<<63 - 1} {
		verifier.now = func() time.Time { return time.Unix(now, 0) }
		assertMentorAdminLookupDenied(t, verifier, domain.MentorCanonicalAdminSubject, request)
	}
}

func mentorAdminCryptoFixture(t *testing.T) (*rsa.PrivateKey, *AuthMentorAdminLookupProofVerifier, *MentorCanonicalAdminDecisionSigner) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewAuthMentorAdminLookupProofVerifier(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub})))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewMentorCanonicalAdminDecisionSigner(string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})))
	if err != nil {
		t.Fatal(err)
	}
	verifier.now = func() time.Time { return time.Unix(mentorAdminTestNow, 0) }
	signer.now = verifier.now
	return key, verifier, signer
}

func mentorAdminLookupTestClaims() map[string]any {
	return map[string]any{"iss": domain.MentorAdminLookupIssuer, "aud": domain.MentorAdminLookupAudience, "sub": mentorAdminTestActor, "typ": domain.MentorAdminLookupType, "purpose": domain.MentorAdminLookupPurpose, "subject": domain.MentorCanonicalAdminSubject, "jti": mentorAdminTestJTI, "iat": mentorAdminTestNow, "exp": mentorAdminTestNow + 30}
}

func assertMentorAdminLookupDenied(t *testing.T, v *AuthMentorAdminLookupProofVerifier, subject, token string) {
	t.Helper()
	if proof, err := v.VerifyMentorAdminLookupProof(context.Background(), subject, token); !errors.Is(err, domain.ErrUnauthenticated) || proof != (domain.MentorAdminLookupProof{}) {
		t.Fatalf("invalid lookup must return zero proof and generic denial: %v", err)
	}
}

func mentorAdminCancelledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func verifyMentorAdminDecision(t *testing.T, key *rsa.PublicKey, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatal("decision is not compact JWT")
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || string(header) != mentorProofTestHeader {
		t.Fatal("unexpected decision header")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal("invalid decision signature encoding")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) != nil {
		t.Fatal("decision signature does not verify")
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal("invalid decision payload encoding")
	}
	var claims map[string]any
	if json.Unmarshal(body, &claims) != nil {
		t.Fatal("invalid decision payload")
	}
	return claims
}
