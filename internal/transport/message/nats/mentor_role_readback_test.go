package nats

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/example/ms-rbac-service/internal/domain"
)

type readbackHandlerVerifier struct {
	proof                   domain.MentorRoleReadbackProof
	calls, failAt, changeAt int
	trace                   *[]string
}

func (v *readbackHandlerVerifier) VerifyMentorRoleReadbackProof(_ context.Context, subject, raw string) (domain.MentorRoleReadbackProof, error) {
	v.calls++
	*v.trace = append(*v.trace, "verify")
	if subject != "rbac.checkRoleScoped.v1" || raw != "request-proof" || v.calls == v.failAt {
		return domain.MentorRoleReadbackProof{}, errors.New("private credential diagnostics")
	}
	p := v.proof
	if v.calls == v.changeAt {
		p.ExpiresAt--
	}
	return p, nil
}

type readbackHandlerLookup struct {
	want   domain.MentorRoleCommand
	result domain.MentorRoleReadbackResult
	err    error
	calls  int
	trace  *[]string
	cancel context.CancelFunc
}

func (l *readbackHandlerLookup) Check(_ context.Context, command domain.MentorRoleCommand) (domain.MentorRoleReadbackResult, error) {
	l.calls++
	*l.trace = append(*l.trace, "read")
	if l.cancel != nil {
		l.cancel()
	}
	if command != l.want {
		return domain.MentorRoleReadbackResult{}, errors.New("wrong admitted binding")
	}
	return l.result, l.err
}

type readbackHandlerSigner struct {
	proof  domain.MentorRoleReadbackProof
	result domain.MentorRoleReadbackResult
	token  string
	err    error
	calls  int
	trace  *[]string
	cancel context.CancelFunc
}

func (s *readbackHandlerSigner) Sign(_ context.Context, p domain.MentorRoleReadbackProof, r domain.MentorRoleReadbackResult) (string, error) {
	s.calls++
	*s.trace = append(*s.trace, "sign")
	s.proof = p
	s.result = r
	if s.cancel != nil {
		s.cancel()
	}
	return s.token, s.err
}

func newReadbackHandlerFixture() (*MentorRoleReadbackConsumer, *readbackHandlerVerifier, *readbackHandlerLookup, *readbackHandlerSigner, *[]string) {
	c := domain.MentorRoleCommand{Issuer: "ms-go-auth", AdminID: "00000000-0000-4000-8000-000000000a01", TargetUserID: "00000000-0000-4000-8000-000000000b01", ApplicationID: "00000000-0000-4000-8000-000000000c01", ApplicationRevision: 2, Decision: "APPROVE", RequestID: "00000000-0000-4000-8000-000000000d01", Role: "mentor", Service: "ms-go-mentor"}
	digest := sha256.Sum256([]byte("APPROVE|" + c.AdminID + "|" + c.ApplicationID + "|" + c.RequestID + "|1"))
	c.DecisionDigest = hex.EncodeToString(digest[:])
	rawDigest := sha256.Sum256([]byte("request-proof"))
	now := time.Now().Unix()
	trace := []string{}
	v := &readbackHandlerVerifier{proof: domain.MentorRoleReadbackProof{Command: c, Subject: "rbac.checkRoleScoped.v1", JWTID: "00000000-0000-4000-8000-000000000e01", ProofDigest: hex.EncodeToString(rawDigest[:]), IssuedAt: now, ExpiresAt: now + 30}, trace: &trace}
	l := &readbackHandlerLookup{want: c, result: domain.MentorRoleReadbackResult{Confirmed: true, Active: true}, trace: &trace}
	s := &readbackHandlerSigner{token: "signed-decision", trace: &trace}
	return &MentorRoleReadbackConsumer{ProofVerifier: v, Lookup: l, DecisionSigner: s}, v, l, s, &trace
}

func TestMentorRoleReadbackHandlerOrdersReadAndExactRevalidation(t *testing.T) {
	for _, result := range []domain.MentorRoleReadbackResult{{Confirmed: true, Active: true}, {}} {
		c, v, l, s, trace := newReadbackHandlerFixture()
		l.result = result
		body, err := c.Handle(context.Background(), "rbac.checkRoleScoped.v1", []byte(`{"proof":"request-proof"}`))
		if err != nil {
			t.Fatalf("valid readback failed: %v", err)
		}
		var reply map[string]string
		if json.Unmarshal(body, &reply) != nil || len(reply) != 1 || reply["decision_jwt"] != "signed-decision" {
			t.Fatal("wrong reply envelope")
		}
		if !reflect.DeepEqual(*trace, []string{"verify", "read", "verify", "sign"}) || s.proof != v.proof || s.result != result || l.calls != 1 {
			t.Fatal("readback skipped exact proof/command binding")
		}
	}
}

func TestMentorRoleReadbackHandlerRejectsBadEnvelopeAndSubjectBeforeDependencies(t *testing.T) {
	for _, body := range []string{"", `{}`, `null`, `[]`, `{"proof":null}`, `{"proof":true}`, `{"proof":""}`, `{"Proof":"request-proof"}`, `{"proof":"request-proof","proof":"request-proof"}`, `{"proof":"request-proof","\u0070roof":"request-proof"}`, `{"proof":"request-proof","user_id":"foreign"}`, `{"proof":"request-proof"}{}`, strings.Repeat("x", 16385), "\xff" + `{"proof":"request-proof"}`} {
		c, _, _, _, trace := newReadbackHandlerFixture()
		assertReadbackHandlerUnavailable(t, c, context.Background(), "rbac.checkRoleScoped.v1", []byte(body))
		if len(*trace) != 0 {
			t.Fatal("invalid envelope reached authority")
		}
	}
	for _, subject := range []string{"", "rbac.checkRole", "rbac.*", "rbac.checkRoleScoped.v1.extra"} {
		c, _, _, _, trace := newReadbackHandlerFixture()
		assertReadbackHandlerUnavailable(t, c, context.Background(), subject, []byte(`{"proof":"request-proof"}`))
		if len(*trace) != 0 {
			t.Fatal("wrong subject reached authority")
		}
	}
}

func TestMentorRoleReadbackHandlerRejectsChangedProofAndNoFalseNegativeOnErrors(t *testing.T) {
	for _, tc := range []struct {
		name         string
		arrange      func(*readbackHandlerVerifier, *readbackHandlerLookup, *readbackHandlerSigner)
		reads, signs int
	}{
		{"bad initial proof", func(v *readbackHandlerVerifier, _ *readbackHandlerLookup, _ *readbackHandlerSigner) { v.failAt = 1 }, 0, 0},
		{"expired after read", func(v *readbackHandlerVerifier, _ *readbackHandlerLookup, _ *readbackHandlerSigner) { v.failAt = 2 }, 1, 0},
		{"changed admitted proof", func(v *readbackHandlerVerifier, _ *readbackHandlerLookup, _ *readbackHandlerSigner) { v.changeAt = 2 }, 1, 0},
		{"wrong raw digest", func(v *readbackHandlerVerifier, _ *readbackHandlerLookup, _ *readbackHandlerSigner) {
			v.proof.ProofDigest = strings.Repeat("0", 64)
		}, 0, 0},
		{"invalid command", func(v *readbackHandlerVerifier, _ *readbackHandlerLookup, _ *readbackHandlerSigner) {
			v.proof.Command.Role = "admin"
		}, 0, 0},
		{"unavailable snapshot", func(_ *readbackHandlerVerifier, l *readbackHandlerLookup, _ *readbackHandlerSigner) {
			l.err = errors.New("private SQL diagnostics")
		}, 1, 0},
		{"active unconfirmed", func(_ *readbackHandlerVerifier, l *readbackHandlerLookup, _ *readbackHandlerSigner) {
			l.result = domain.MentorRoleReadbackResult{Active: true}
		}, 1, 0},
		{"inactive approval", func(_ *readbackHandlerVerifier, l *readbackHandlerLookup, _ *readbackHandlerSigner) {
			l.result = domain.MentorRoleReadbackResult{Confirmed: true}
		}, 1, 0},
		{"signing failed", func(_ *readbackHandlerVerifier, _ *readbackHandlerLookup, s *readbackHandlerSigner) {
			s.err = errors.New("private key diagnostic")
		}, 1, 1},
		{"empty signature", func(_ *readbackHandlerVerifier, _ *readbackHandlerLookup, s *readbackHandlerSigner) { s.token = "" }, 1, 1},
		{"oversized signature", func(_ *readbackHandlerVerifier, _ *readbackHandlerLookup, s *readbackHandlerSigner) {
			s.token = strings.Repeat("x", 8193)
		}, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, v, l, s, _ := newReadbackHandlerFixture()
			tc.arrange(v, l, s)
			assertReadbackHandlerUnavailable(t, c, context.Background(), "rbac.checkRoleScoped.v1", []byte(`{"proof":"request-proof"}`))
			if l.calls != tc.reads || s.calls != tc.signs {
				t.Fatalf("unexpected reads/signs: %d/%d", l.calls, s.calls)
			}
		})
	}
}

func TestMentorRoleReadbackHandlerNilAndCancellation(t *testing.T) {
	for _, stage := range []string{"before", "during read", "during sign"} {
		c, _, l, s, _ := newReadbackHandlerFixture()
		ctx, cancel := context.WithCancel(context.Background())
		switch stage {
		case "before":
			cancel()
		case "during read":
			l.cancel = cancel
		case "during sign":
			s.cancel = cancel
		}
		assertReadbackHandlerUnavailable(t, c, ctx, "rbac.checkRoleScoped.v1", []byte(`{"proof":"request-proof"}`))
		cancel()
	}
	for _, dependency := range []string{"consumer", "verifier", "lookup", "signer", "typed verifier", "typed lookup", "typed signer"} {
		c, _, _, _, _ := newReadbackHandlerFixture()
		switch dependency {
		case "consumer":
			c = nil
		case "verifier":
			c.ProofVerifier = nil
		case "lookup":
			c.Lookup = nil
		case "signer":
			c.DecisionSigner = nil
		case "typed verifier":
			c.ProofVerifier = (*readbackHandlerVerifier)(nil)
		case "typed lookup":
			c.Lookup = (*readbackHandlerLookup)(nil)
		case "typed signer":
			c.DecisionSigner = (*readbackHandlerSigner)(nil)
		}
		assertReadbackHandlerUnavailable(t, c, context.Background(), "rbac.checkRoleScoped.v1", []byte(`{"proof":"request-proof"}`))
	}
	c, _, _, _, _ := newReadbackHandlerFixture()
	assertReadbackHandlerUnavailable(t, c, nil, "rbac.checkRoleScoped.v1", []byte(`{"proof":"request-proof"}`))
}

func assertReadbackHandlerUnavailable(t *testing.T, c *MentorRoleReadbackConsumer, ctx context.Context, subject string, body []byte) {
	t.Helper()
	reply, err := c.Handle(ctx, subject, body)
	if err != domain.ErrAuthorityUnavailable || len(reply) != 0 {
		t.Fatalf("must return zero reply and generic unavailable: %v", err)
	}
}
