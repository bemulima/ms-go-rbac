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
	"github.com/example/ms-rbac-service/internal/usecase"
)

type mentorAdminVerifierFixture struct {
	proof    domain.MentorAdminLookupProof
	calls    int
	failAt   int
	changeAt int
	trace    *[]string
}

func (f *mentorAdminVerifierFixture) VerifyMentorAdminLookupProof(_ context.Context, subject, raw string) (domain.MentorAdminLookupProof, error) {
	f.calls++
	*f.trace = append(*f.trace, "verify")
	if subject != domain.MentorCanonicalAdminSubject || raw != "request-proof" || f.calls == f.failAt {
		return domain.MentorAdminLookupProof{}, errors.New("private verification detail")
	}
	proof := f.proof
	if f.calls == f.changeAt {
		proof.ActorID = "00000000-0000-4000-8000-000000000a02"
	}
	return proof, nil
}

type mentorAdminRoleReaderFixture struct {
	role   string
	err    error
	calls  int
	trace  *[]string
	cancel context.CancelFunc
}

func (f *mentorAdminRoleReaderFixture) GetDefaultRole(_ context.Context, actor string) (string, error) {
	f.calls++
	*f.trace = append(*f.trace, "read")
	if f.cancel != nil {
		f.cancel()
	}
	if actor != "00000000-0000-4000-8000-000000000a01" {
		return "", errors.New("unexpected actor")
	}
	return f.role, f.err
}

type mentorAdminSignerFixture struct {
	calls   int
	allowed bool
	proof   domain.MentorAdminLookupProof
	err     error
	result  string
	trace   *[]string
	cancel  context.CancelFunc
}

func (f *mentorAdminSignerFixture) Sign(_ context.Context, proof domain.MentorAdminLookupProof, allowed bool) (string, error) {
	f.calls++
	*f.trace = append(*f.trace, "sign")
	f.allowed = allowed
	f.proof = proof
	if f.cancel != nil {
		f.cancel()
	}
	return f.result, f.err
}

func mentorAdminConsumerFixture() (*MentorCanonicalAdminConsumer, *mentorAdminVerifierFixture, *mentorAdminRoleReaderFixture, *mentorAdminSignerFixture, *[]string) {
	trace := []string{}
	digest := sha256.Sum256([]byte("request-proof"))
	now := time.Now().Unix()
	proof := domain.MentorAdminLookupProof{ActorID: "00000000-0000-4000-8000-000000000a01", Subject: domain.MentorCanonicalAdminSubject, JWTID: "00000000-0000-4000-8000-000000000e01", ProofDigest: hex.EncodeToString(digest[:]), IssuedAt: now, ExpiresAt: now + 30}
	verifier := &mentorAdminVerifierFixture{proof: proof, trace: &trace}
	reader := &mentorAdminRoleReaderFixture{role: "admin", trace: &trace}
	signer := &mentorAdminSignerFixture{result: "signed-decision", trace: &trace}
	return &MentorCanonicalAdminConsumer{ProofVerifier: verifier, Lookup: usecase.NewMentorCanonicalAdminLookup(reader), DecisionSigner: signer}, verifier, reader, signer, &trace
}

func TestMentorCanonicalAdminConsumerVerifiesReadsReverifiesThenSigns(t *testing.T) {
	for _, tc := range []struct {
		role  string
		allow bool
	}{{"admin", true}, {"student", false}, {"", false}} {
		t.Run(tc.role, func(t *testing.T) {
			consumer, verifier, reader, signer, trace := mentorAdminConsumerFixture()
			reader.role = tc.role
			body, err := consumer.Handle(context.Background(), domain.MentorCanonicalAdminSubject, []byte(`{"proof":"request-proof"}`))
			if err != nil {
				t.Fatalf("known current state must yield signed decision: %v", err)
			}
			var reply map[string]string
			if json.Unmarshal(body, &reply) != nil || len(reply) != 1 || reply["decision_jwt"] != "signed-decision" {
				t.Fatal("response did not contain exactly owner decision JWT")
			}
			if !reflect.DeepEqual(*trace, []string{"verify", "read", "verify", "sign"}) || verifier.calls != 2 || reader.calls != 1 || signer.calls != 1 || signer.allowed != tc.allow || signer.proof != verifier.proof {
				t.Fatal("provider did not preserve verify/read/reverify/sign ordering and proof binding")
			}
		})
	}
}

func TestMentorCanonicalAdminConsumerRejectsMalformedRequestsBeforeRead(t *testing.T) {
	for _, body := range []string{"", `{}`, `null`, `[]`, `{"proof":null}`, `{"proof":true}`, `{"proof":""}`, `{"Proof":"request-proof"}`, `{"proof":"request-proof","proof":"request-proof"}`, `{"proof":"request-proof","\u0070roof":"request-proof"}`, `{"proof":"request-proof","actor_id":"other"}`, `{"proof":"request-proof"}{}`, strings.Repeat("a", 16385)} {
		consumer, verifier, reader, signer, _ := mentorAdminConsumerFixture()
		assertMentorAdminHandlerUnavailable(t, consumer, context.Background(), domain.MentorCanonicalAdminSubject, []byte(body))
		if verifier.calls != 0 || reader.calls != 0 || signer.calls != 0 {
			t.Fatal("invalid envelope reached a dependency")
		}
	}
	consumer, verifier, reader, signer, _ := mentorAdminConsumerFixture()
	for _, subject := range []string{"", domain.MentorCanonicalAdminSubject + ".other", "rbac.checkPermission", "rbac.*"} {
		assertMentorAdminHandlerUnavailable(t, consumer, context.Background(), subject, []byte(`{"proof":"request-proof"}`))
	}
	if verifier.calls != 0 || reader.calls != 0 || signer.calls != 0 {
		t.Fatal("wrong actual subject reached a dependency")
	}
}

func TestMentorCanonicalAdminConsumerDeniesBeforeOrAfterReadWithoutFalseDenial(t *testing.T) {
	for _, tc := range []struct {
		name      string
		arrange   func(*mentorAdminVerifierFixture, *mentorAdminRoleReaderFixture, *mentorAdminSignerFixture)
		wantReads int
		wantSigns int
	}{
		{"invalid initial proof", func(v *mentorAdminVerifierFixture, _ *mentorAdminRoleReaderFixture, _ *mentorAdminSignerFixture) {
			v.failAt = 1
		}, 0, 0},
		{"expired after read", func(v *mentorAdminVerifierFixture, _ *mentorAdminRoleReaderFixture, _ *mentorAdminSignerFixture) {
			v.failAt = 2
		}, 1, 0},
		{"changed reverified binding", func(v *mentorAdminVerifierFixture, _ *mentorAdminRoleReaderFixture, _ *mentorAdminSignerFixture) {
			v.changeAt = 2
		}, 1, 0},
		{"ambiguous default", func(_ *mentorAdminVerifierFixture, r *mentorAdminRoleReaderFixture, _ *mentorAdminSignerFixture) {
			r.err = domain.ErrAmbiguousPrincipalRole
		}, 1, 0},
		{"unavailable store", func(_ *mentorAdminVerifierFixture, r *mentorAdminRoleReaderFixture, _ *mentorAdminSignerFixture) {
			r.err = errors.New("sensitive store diagnostic")
		}, 1, 0},
		{"signer failure", func(_ *mentorAdminVerifierFixture, _ *mentorAdminRoleReaderFixture, s *mentorAdminSignerFixture) {
			s.err = errors.New("sensitive signer diagnostic")
		}, 1, 1},
		{"empty signature", func(_ *mentorAdminVerifierFixture, _ *mentorAdminRoleReaderFixture, s *mentorAdminSignerFixture) {
			s.result = ""
		}, 1, 1},
		{"oversized signature", func(_ *mentorAdminVerifierFixture, _ *mentorAdminRoleReaderFixture, s *mentorAdminSignerFixture) {
			s.result = strings.Repeat("a", 8193)
		}, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			consumer, verifier, reader, signer, _ := mentorAdminConsumerFixture()
			tc.arrange(verifier, reader, signer)
			assertMentorAdminHandlerUnavailable(t, consumer, context.Background(), domain.MentorCanonicalAdminSubject, []byte(`{"proof":"request-proof"}`))
			if reader.calls != tc.wantReads || signer.calls != tc.wantSigns {
				t.Fatalf("invalid dependency ordering: reads=%d signs=%d", reader.calls, signer.calls)
			}
		})
	}
}

func TestMentorCanonicalAdminConsumerMissingDependenciesAndCancellation(t *testing.T) {
	var typedVerifier *mentorAdminVerifierFixture
	var typedLookup *usecase.MentorCanonicalAdminLookup
	var typedSigner *mentorAdminSignerFixture
	for _, consumer := range []*MentorCanonicalAdminConsumer{nil, {}, {ProofVerifier: typedVerifier}, {Lookup: typedLookup}, {DecisionSigner: typedSigner}} {
		assertMentorAdminHandlerUnavailable(t, consumer, context.Background(), domain.MentorCanonicalAdminSubject, []byte(`{"proof":"request-proof"}`))
	}
	for _, missing := range []string{"verifier", "lookup", "signer"} {
		consumer, verifier, reader, signer, _ := mentorAdminConsumerFixture()
		switch missing {
		case "verifier":
			consumer.ProofVerifier = typedVerifier
		case "lookup":
			consumer.Lookup = typedLookup
		case "signer":
			consumer.DecisionSigner = typedSigner
		}
		assertMentorAdminHandlerUnavailable(t, consumer, context.Background(), domain.MentorCanonicalAdminSubject, []byte(`{"proof":"request-proof"}`))
		if verifier.calls != 0 || reader.calls != 0 || signer.calls != 0 {
			t.Fatal("typed-nil dependency did not stop before any dependency access")
		}
	}
	for _, phase := range []string{"nil", "before", "read", "sign"} {
		t.Run(phase, func(t *testing.T) {
			consumer, verifier, reader, signer, _ := mentorAdminConsumerFixture()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if phase == "nil" {
				ctx = nil
			}
			if phase == "before" {
				cancel()
			}
			if phase == "read" {
				reader.cancel = cancel
			}
			if phase == "sign" {
				signer.cancel = cancel
			}
			assertMentorAdminHandlerUnavailable(t, consumer, ctx, domain.MentorCanonicalAdminSubject, []byte(`{"proof":"request-proof"}`))
			if (phase == "nil" || phase == "before") && (verifier.calls != 0 || reader.calls != 0 || signer.calls != 0) {
				t.Fatal("cancelled request reached a dependency")
			}
			if phase == "read" && signer.calls != 0 {
				t.Fatal("cancelled read reached signer")
			}
		})
	}
}

func assertMentorAdminHandlerUnavailable(t *testing.T, consumer *MentorCanonicalAdminConsumer, ctx context.Context, subject string, body []byte) {
	t.Helper()
	response, err := consumer.Handle(ctx, subject, body)
	if response != nil || err != domain.ErrAuthorityUnavailable {
		t.Fatal("failure must return no confirmation and only generic unavailable error")
	}
}
