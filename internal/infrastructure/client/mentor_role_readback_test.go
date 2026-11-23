package client

import (
	"context"
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

const readbackNow int64 = 1800000000

func readbackCommand() domain.MentorRoleCommand {
	c := domain.MentorRoleCommand{Issuer: "ms-go-auth", AdminID: "00000000-0000-4000-8000-000000000a01", TargetUserID: "00000000-0000-4000-8000-000000000b01", ApplicationID: "00000000-0000-4000-8000-000000000c01", ApplicationRevision: 2, Decision: "APPROVE", RequestID: "00000000-0000-4000-8000-000000000d01", Role: "mentor", Service: "ms-go-mentor"}
	readbackDigest(&c)
	return c
}

func readbackDigest(c *domain.MentorRoleCommand) {
	sum := sha256.Sum256([]byte(c.Decision + "|" + c.AdminID + "|" + c.ApplicationID + "|" + c.RequestID + "|" + strconv.FormatUint(c.ApplicationRevision-1, 10)))
	c.DecisionDigest = hex.EncodeToString(sum[:])
}

func readbackClaims(c domain.MentorRoleCommand) map[string]any {
	return map[string]any{"iss": "ms-go-mentor", "aud": "ms-go-rbac-mentor-role-readback", "sub": c.TargetUserID, "typ": "mentor_role_readback_check", "purpose": "MENTOR_RBAC_SCOPED_ROLE_READBACK_V1", "subject": "rbac.checkRoleScoped.v1", "jti": "00000000-0000-4000-8000-000000000e01", "iat": readbackNow, "exp": readbackNow + 30, "admin_actor_id": c.AdminID, "application_id": c.ApplicationID, "application_revision": c.ApplicationRevision, "decision": c.Decision, "request_id": c.RequestID, "decision_digest": c.DecisionDigest, "role_key": c.Role, "service_key": c.Service}
}

func readbackProof(c domain.MentorRoleCommand, raw string) domain.MentorRoleReadbackProof {
	sum := sha256.Sum256([]byte(raw))
	return domain.MentorRoleReadbackProof{Command: c, Subject: "rbac.checkRoleScoped.v1", JWTID: "00000000-0000-4000-8000-000000000e01", ProofDigest: hex.EncodeToString(sum[:]), IssuedAt: readbackNow, ExpiresAt: readbackNow + 30}
}

func readbackKeys(t *testing.T) (*rsa.PrivateKey, string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}))
}

func TestMentorRoleReadbackVerifierAcceptsExactCommandsAndProofBytes(t *testing.T) {
	key, _, pub := readbackKeys(t)
	v, err := NewMentorRoleReadbackProofVerifier(pub)
	if err != nil {
		t.Fatal(err)
	}
	v.now = func() time.Time { return time.Unix(readbackNow, 0) }
	for _, revision := range []uint64{2, 3, 4} {
		t.Run(strconv.FormatUint(revision, 10), func(t *testing.T) {
			command := readbackCommand()
			command.ApplicationRevision = revision
			if revision > 2 {
				command.Decision = "SUSPEND"
			}
			readbackDigest(&command)
			raw := signMentorProof(t, key, mentorProofTestHeader, marshalMentorProofClaims(t, readbackClaims(command)))
			got, err := v.VerifyMentorRoleReadbackProof(context.Background(), "rbac.checkRoleScoped.v1", raw)
			if err != nil || got != readbackProof(command, raw) {
				t.Fatalf("exact dedicated request rejected: %v", err)
			}
		})
	}
}

func TestMentorRoleReadbackVerifierRejectsEveryClaimShape(t *testing.T) {
	key, _, pub := readbackKeys(t)
	v, _ := NewMentorRoleReadbackProofVerifier(pub)
	v.now = func() time.Time { return time.Unix(readbackNow, 0) }
	for field := range readbackClaims(readbackCommand()) {
		t.Run(field, func(t *testing.T) {
			for _, shape := range []string{"missing", "null", "wrong-type", "case-alias", "duplicate", "escaped-duplicate"} {
				t.Run(shape, func(t *testing.T) {
					claims := readbackClaims(readbackCommand())
					var body []byte
					switch shape {
					case "missing":
						delete(claims, field)
					case "null":
						claims[field] = nil
					case "wrong-type":
						claims[field] = true
					case "case-alias":
						claims[strings.ToUpper(field)] = claims[field]
						delete(claims, field)
					default:
						name, _ := json.Marshal(field)
						value, _ := json.Marshal(claims[field])
						if shape == "escaped-duplicate" {
							name = []byte(`"\u00` + strconv.FormatInt(int64(field[0]), 16) + field[1:] + `"`)
						}
						body = []byte(strings.TrimSuffix(string(marshalMentorProofClaims(t, claims)), "}") + "," + string(name) + ":" + string(value) + "}")
					}
					if body == nil {
						body = marshalMentorProofClaims(t, claims)
					}
					assertReadbackProofDenied(t, v, "rbac.checkRoleScoped.v1", signMentorProof(t, key, mentorProofTestHeader, body))
				})
			}
		})
	}
}

func TestMentorRoleReadbackVerifierRejectsChangedAuthorityAndEncoding(t *testing.T) {
	key, _, pub := readbackKeys(t)
	v, _ := NewMentorRoleReadbackProofVerifier(pub)
	v.now = func() time.Time { return time.Unix(readbackNow, 0) }
	for _, tc := range []struct {
		field string
		value any
	}{
		{"iss", "ms-go-auth"}, {"aud", domain.MentorRoleProofAudience}, {"typ", domain.MentorRoleProofType}, {"purpose", domain.MentorRoleProofPurpose}, {"subject", "rbac.checkRole"}, {"role_key", "admin"}, {"service_key", "core"}, {"sub", "00000000-0000-0000-0000-000000000000"}, {"admin_actor_id", "not-uuid"}, {"application_id", "00000000-0000-4000-8000-000000000C01"}, {"request_id", "bad"}, {"decision_digest", strings.Repeat("0", 64)}, {"decision", "REJECT"}, {"application_revision", 3}, {"jti", "bad"}, {"iat", 0}, {"iat", readbackNow + 6}, {"exp", readbackNow}, {"exp", readbackNow + 31}, {"exp", int64(1 << 53)}, {"extra", "value"},
	} {
		claims := readbackClaims(readbackCommand())
		claims[tc.field] = tc.value
		assertReadbackProofDenied(t, v, "rbac.checkRoleScoped.v1", signMentorProof(t, key, mentorProofTestHeader, marshalMentorProofClaims(t, claims)))
	}
	for _, field := range []string{"iat", "exp", "application_revision"} {
		for _, value := range []string{"2.0", "2e0", `"2"`, "18446744073709551616", "-1"} {
			claims := readbackClaims(readbackCommand())
			claims[field] = json.RawMessage(value)
			assertReadbackProofDenied(t, v, "rbac.checkRoleScoped.v1", signMentorProof(t, key, mentorProofTestHeader, marshalMentorProofClaims(t, claims)))
		}
	}
	body := marshalMentorProofClaims(t, readbackClaims(readbackCommand()))
	for _, header := range []string{`{"alg":"none","typ":"JWT"}`, `{"alg":"HS256","typ":"JWT"}`, `{"alg":"RS256","typ":"JWT","kid":"foreign"}`, `{"alg":"RS256","alg":"RS256","typ":"JWT"}`, `{"alg":"RS256","\u0061lg":"RS256","typ":"JWT"}`, `{"Alg":"RS256","typ":"JWT"}`, `{"alg":"RS256"}`, mentorProofTestHeader + `{}`} {
		assertReadbackProofDenied(t, v, "rbac.checkRoleScoped.v1", signMentorProof(t, key, header, body))
	}
	valid := signMentorProof(t, key, mentorProofTestHeader, body)
	parts := strings.Split(valid, ".")
	for _, raw := range []string{"", valid + "=", valid + ".extra", parts[0] + "\n." + parts[1] + "." + parts[2], parts[0] + "." + parts[1] + "=." + parts[2], parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{}`)) + "." + parts[2], strings.Repeat("x", 8193)} {
		assertReadbackProofDenied(t, v, "rbac.checkRoleScoped.v1", raw)
	}
	other, _, _ := readbackKeys(t)
	assertReadbackProofDenied(t, v, "rbac.checkRoleScoped.v1", signMentorProof(t, other, mentorProofTestHeader, body))
	assertReadbackProofDenied(t, v, "rbac.checkRole", valid)
	for _, payload := range [][]byte{[]byte(`null`), []byte(`[]`), append(append([]byte{}, body...), []byte(`{}`)...), append([]byte{'\xff'}, body...)} {
		assertReadbackProofDenied(t, v, "rbac.checkRoleScoped.v1", signMentorProof(t, key, mentorProofTestHeader, payload))
	}
}

func TestMentorRoleReadbackSignerBindsExactCommandFreshNoncesAndResults(t *testing.T) {
	key, priv, pub := readbackKeys(t)
	s, err := NewMentorRoleReadbackDecisionSigner(priv, pub)
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return time.Unix(readbackNow, 0) }
	seen := map[string]bool{}
	for _, tc := range []struct {
		revision          uint64
		confirmed, active bool
		result, state     string
	}{{2, true, true, "ALLOW", "ACTIVE"}, {3, true, false, "ALLOW", "INACTIVE"}, {4, true, false, "ALLOW", "INACTIVE"}, {2, false, false, "DENY", "UNCONFIRMED"}} {
		c := readbackCommand()
		c.ApplicationRevision = tc.revision
		if tc.revision > 2 {
			c.Decision = "SUSPEND"
		}
		readbackDigest(&c)
		p := readbackProof(c, "exact-original-request")
		raw, err := s.Sign(context.Background(), p, domain.MentorRoleReadbackResult{Confirmed: tc.confirmed, Active: tc.active})
		if err != nil {
			t.Fatalf("valid owner observation rejected: %v", err)
		}
		claims := verifyMentorAdminDecision(t, &key.PublicKey, raw)
		want := readbackClaims(c)
		want["iss"] = "ms-go-rbac"
		want["aud"] = "ms-go-mentor-scoped-role-readback"
		want["typ"] = "mentor_role_readback_decision"
		want["purpose"] = "RBAC_MENTOR_SCOPED_ROLE_READBACK_DECISION_V1"
		delete(want, "jti")
		want["iat"] = float64(readbackNow)
		want["exp"] = float64(readbackNow + 15)
		want["application_revision"] = float64(c.ApplicationRevision)
		want["result"] = tc.result
		want["state"] = tc.state
		want["request_jti"] = p.JWTID
		want["request_digest"] = p.ProofDigest
		if len(claims) != 21 {
			t.Fatal("unexpected decision claim set")
		}
		for k, w := range want {
			if claims[k] != w {
				t.Fatalf("wrong binding for %s", k)
			}
		}
		jti, _ := claims["jti"].(string)
		if !domain.ValidPrincipalID(jti) || seen[jti] || jti == p.JWTID {
			t.Fatal("reply nonce not fresh")
		}
		seen[jti] = true
	}
}

func TestMentorRoleReadbackCryptoFailsClosedAtFinalTimeAndCancellation(t *testing.T) {
	key, priv, pub := readbackKeys(t)
	v, _ := NewMentorRoleReadbackProofVerifier(pub)
	s, _ := NewMentorRoleReadbackDecisionSigner(priv, pub)
	raw := signMentorProof(t, key, mentorProofTestHeader, marshalMentorProofClaims(t, readbackClaims(readbackCommand())))
	p := readbackProof(readbackCommand(), raw)
	v.now = func() time.Time { return time.Unix(readbackNow+30, 0) }
	assertReadbackProofDenied(t, v, "rbac.checkRoleScoped.v1", raw)
	for _, ctx := range []context.Context{nil, mentorAdminCancelledContext()} {
		if got, err := v.VerifyMentorRoleReadbackProof(ctx, "rbac.checkRoleScoped.v1", raw); err == nil || got != (domain.MentorRoleReadbackProof{}) {
			t.Fatal("cancelled verifier accepted")
		}
		if got, err := s.Sign(ctx, p, domain.MentorRoleReadbackResult{Confirmed: true, Active: true}); err == nil || got != "" {
			t.Fatal("cancelled signer accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	v.now = func() time.Time { cancel(); return time.Unix(readbackNow, 0) }
	if got, err := v.VerifyMentorRoleReadbackProof(ctx, "rbac.checkRoleScoped.v1", raw); err == nil || got != (domain.MentorRoleReadbackProof{}) {
		t.Fatal("late cancellation ignored")
	}
	s.now = func() time.Time { return time.Unix(readbackNow+25, 0) }
	signed, err := s.Sign(context.Background(), p, domain.MentorRoleReadbackResult{Confirmed: true, Active: true})
	if err != nil || verifyMentorAdminDecision(t, &key.PublicKey, signed)["exp"] != float64(p.ExpiresAt) {
		t.Fatal("reply expiry not capped to request")
	}
	for _, finish := range []int64{readbackNow + 15, readbackNow + 30, readbackNow - 6} {
		calls := 0
		s.now = func() time.Time {
			calls++
			if calls == 1 {
				return time.Unix(readbackNow, 0)
			}
			return time.Unix(finish, 0)
		}
		if got, err := s.Sign(context.Background(), p, domain.MentorRoleReadbackResult{Confirmed: true, Active: true}); err == nil || got != "" {
			t.Fatal("expired or clock-shifted signed response escaped")
		}
	}
	s.now = func() time.Time { return time.Unix(readbackNow, 0) }
	for _, r := range []domain.MentorRoleReadbackResult{{Confirmed: false, Active: true}, {Confirmed: true, Active: false}} {
		if raw, err := s.Sign(context.Background(), p, r); err == nil || raw != "" {
			t.Fatal("inconsistent result signed")
		}
	}
	for _, mutate := range []func(*domain.MentorRoleReadbackProof){func(p *domain.MentorRoleReadbackProof) { p.Command.DecisionDigest = "bad" }, func(p *domain.MentorRoleReadbackProof) { p.Subject = "other" }, func(p *domain.MentorRoleReadbackProof) { p.JWTID = "bad" }, func(p *domain.MentorRoleReadbackProof) { p.ProofDigest = strings.Repeat("A", 64) }, func(p *domain.MentorRoleReadbackProof) { p.ExpiresAt = p.IssuedAt + 31 }} {
		bad := p
		mutate(&bad)
		if raw, err := s.Sign(context.Background(), bad, domain.MentorRoleReadbackResult{Confirmed: true, Active: true}); err == nil || raw != "" {
			t.Fatal("malformed proof signed")
		}
	}
}

func TestMentorRoleReadbackCryptoRejectsUnconfiguredAndMismatchedKeys(t *testing.T) {
	_, priv, pub := readbackKeys(t)
	_, otherPriv, otherPub := readbackKeys(t)
	for _, key := range []string{"", "garbage", pub + pub, "prefix" + pub, priv} {
		if _, err := NewMentorRoleReadbackProofVerifier(key); err == nil {
			t.Fatal("invalid dedicated request key accepted")
		}
	}
	for _, keys := range [][2]string{{"", ""}, {priv, otherPub}, {otherPriv, pub}, {priv + priv, pub}, {priv, pub + pub}, {"prefix" + priv, pub}, {pub, pub}} {
		if _, err := NewMentorRoleReadbackDecisionSigner(keys[0], keys[1]); err == nil {
			t.Fatal("invalid or unmatched signer pair accepted")
		}
	}
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	weakPub := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&weak.PublicKey)}))
	if _, err := NewMentorRoleReadbackProofVerifier(weakPub); err == nil {
		t.Fatal("weak key accepted")
	}
	for _, v := range []*MentorRoleReadbackProofVerifier{nil, {}} {
		if p, err := v.VerifyMentorRoleReadbackProof(context.Background(), "rbac.checkRoleScoped.v1", "proof"); err == nil || p != (domain.MentorRoleReadbackProof{}) {
			t.Fatal("missing verifier failed open")
		}
	}
	for _, s := range []*MentorRoleReadbackDecisionSigner{nil, {}} {
		if raw, err := s.Sign(context.Background(), readbackProof(readbackCommand(), "proof"), domain.MentorRoleReadbackResult{Confirmed: true, Active: true}); err == nil || raw != "" {
			t.Fatal("missing signer failed open")
		}
	}
}

func assertReadbackProofDenied(t *testing.T, v *MentorRoleReadbackProofVerifier, subject, raw string) {
	t.Helper()
	if p, err := v.VerifyMentorRoleReadbackProof(context.Background(), subject, raw); !errors.Is(err, domain.ErrUnauthenticated) || p != (domain.MentorRoleReadbackProof{}) {
		t.Fatalf("invalid request did not return zero proof/denial: %v", err)
	}
}
