package nats

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
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/example/ms-rbac-service/internal/domain"
	"github.com/example/ms-rbac-service/internal/infrastructure/client"
	"github.com/example/ms-rbac-service/internal/usecase"
)

// This is a test-only command/fence fixture, never a production authority store.
// Actual handler, use case and signature verification remain in the tested path.
type mentorMutationRPCStore struct {
	mu            sync.Mutex
	calls         int
	writes        int
	rechecks      int
	receipts      map[string]domain.MentorRoleCommandReceipt
	current       *domain.MentorRoleFence
	failure       error
	loseCommitACK bool
	invalidResult bool
	before        func(context.Context, domain.MentorRoleProof)
	afterCommit   func()
	lastProof     domain.MentorRoleProof
}

func (s *mentorMutationRPCStore) ApplyMentorRole(ctx context.Context, proof domain.MentorRoleProof, revalidate domain.MentorRoleProofRevalidator) (domain.MentorRolePlan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.lastProof = proof
	if s.before != nil {
		s.before(ctx, proof)
	}
	if s.failure != nil {
		return domain.MentorRolePlan{}, s.failure
	}
	for range 3 {
		checked, err := revalidate(ctx)
		s.rechecks++
		if err != nil {
			return domain.MentorRolePlan{}, err
		}
		if checked != proof {
			return domain.MentorRolePlan{}, domain.ErrMentorRoleInvalidSnapshot
		}
	}
	var previous *domain.MentorRoleCommandReceipt
	if receipt, exists := s.receipts[proof.Command.RequestID]; exists {
		previous = &receipt
	}
	plan, err := domain.PlanMentorRoleCommand(proof.Command, domain.MentorRoleSnapshot{
		Receipt: previous, ApplicationFence: s.current, TargetFence: s.current,
	})
	if err != nil {
		return domain.MentorRolePlan{}, err
	}
	if s.invalidResult {
		plan.Current.Active = !plan.Current.Active
		return plan, nil
	}
	if plan.Write {
		if s.receipts == nil {
			s.receipts = map[string]domain.MentorRoleCommandReceipt{}
		}
		s.receipts[proof.Command.RequestID] = plan.Receipt
		current := plan.Current
		s.current = &current
		s.writes++
	}
	if s.afterCommit != nil {
		s.afterCommit()
	}
	if s.loseCommitACK {
		s.loseCommitACK = false
		return domain.MentorRolePlan{}, errors.New("private uncertain commit diagnostics")
	}
	return plan, nil
}

var mentorMutationRPCKeys struct {
	once sync.Once
	key  *rsa.PrivateKey
	err  error
}

func mentorMutationRPCKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	mentorMutationRPCKeys.once.Do(func() {
		mentorMutationRPCKeys.key, mentorMutationRPCKeys.err = rsa.GenerateKey(rand.Reader, 2048)
	})
	if mentorMutationRPCKeys.err != nil {
		t.Fatal("test key generation failed")
	}
	return mentorMutationRPCKeys.key
}

func mentorMutationRPCFixture(t *testing.T) (*MentorRoleMutationConsumer, *mentorMutationRPCStore) {
	t.Helper()
	encoded, err := x509.MarshalPKIXPublicKey(&mentorMutationRPCKey(t).PublicKey)
	if err != nil {
		t.Fatal("test public key encoding failed")
	}
	public := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded}))
	verifier, err := client.NewAuthMentorRoleProofVerifier(public)
	if err != nil {
		t.Fatal("actual verifier construction failed")
	}
	store := &mentorMutationRPCStore{}
	return &MentorRoleMutationConsumer{Mutation: usecase.NewMentorRoleMutation(verifier, store)}, store
}

func mentorMutationRPCClaims(decision string, revision uint64) map[string]any {
	request := "00000000-0000-4000-8000-000000000d01"
	if decision == "SUSPEND" {
		request = "00000000-0000-4000-8000-000000000d02"
	}
	now := time.Now().Unix()
	claims := map[string]any{
		"iss": "ms-go-auth", "aud": "ms-go-rbac-mentor-role",
		"sub": "00000000-0000-4000-8000-000000000a01", "typ": "mentor_role_decision",
		"purpose":              "AUTH_RBAC_MENTOR_ROLE_DECISION_V1",
		"target_user_id":       "00000000-0000-4000-8000-000000000b01",
		"application_id":       "00000000-0000-4000-8000-000000000c01",
		"application_revision": revision, "decision": decision, "request_id": request,
		"role": "mentor", "service": "ms-go-mentor",
		"jti": "00000000-0000-4000-8000-000000000e01", "iat": now, "exp": now + 30,
	}
	digest := sha256.Sum256([]byte(decision + "|" + claims["sub"].(string) + "|" + claims["application_id"].(string) + "|" + request + "|" + strconv.FormatUint(revision-1, 10)))
	claims["decision_digest"] = hex.EncodeToString(digest[:])
	return claims
}

func mentorMutationRPCSignWithKey(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatal("test claims encoding failed")
	}
	signingInput := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString(body)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal("test signing failed")
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func mentorMutationRPCSign(t *testing.T, claims map[string]any) string {
	t.Helper()
	return mentorMutationRPCSignWithKey(t, mentorMutationRPCKey(t), claims)
}

func mentorMutationRPCEnvelope(t *testing.T, raw string) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]string{"proof": raw})
	if err != nil {
		t.Fatal("test request encoding failed")
	}
	return body
}

func assertMentorMutationRPCReply(t *testing.T, c *MentorRoleMutationConsumer, ctx context.Context, body []byte, wanted string) {
	t.Helper()
	actual, err := c.Handle(ctx, MentorRoleMutationSubject, body)
	if err != nil || string(actual) != wanted {
		t.Fatalf("wrong fixed RPC outcome; err=%v responseBytes=%d", err, len(actual))
	}
}

func TestMentorRoleMutationRPCActualProofAdmissionAndExactACK(t *testing.T) {
	for _, tc := range []struct {
		decision string
		revision uint64
	}{{"APPROVE", 2}, {"SUSPEND", 3}, {"SUSPEND", 4}} {
		t.Run(tc.decision+strconv.FormatUint(tc.revision, 10), func(t *testing.T) {
			c, store := mentorMutationRPCFixture(t)
			claims := mentorMutationRPCClaims(tc.decision, tc.revision)
			raw := mentorMutationRPCSign(t, claims)
			assertMentorMutationRPCReply(t, c, context.Background(), mentorMutationRPCEnvelope(t, raw), `{"ok":true}`)
			digest := sha256.Sum256([]byte(raw))
			if store.calls != 1 || store.writes != 1 || store.rechecks != 3 || store.lastProof.ProofDigest != hex.EncodeToString(digest[:]) || store.lastProof.Command.Decision != tc.decision || store.lastProof.Command.ApplicationRevision != tc.revision {
				t.Fatal("actual use case did not admit and revalidate exact signed command")
			}
			if store.current.Active != (tc.decision == "APPROVE") {
				t.Fatal("controlled owner fixture applied wrong command")
			}
		})
	}
}

func TestMentorRoleMutationRPCStrictEnvelopeBeforeStore(t *testing.T) {
	valid := string(mentorMutationRPCEnvelope(t, mentorMutationRPCSign(t, mentorMutationRPCClaims("APPROVE", 2))))
	cases := []struct{ name, body string }{
		{"empty", ""}, {"missing", `{}`}, {"null object", `null`}, {"array", `[]`},
		{"null proof", `{"proof":null}`}, {"bool proof", `{"proof":true}`}, {"number proof", `{"proof":1}`},
		{"empty proof", `{"proof":""}`}, {"whitespace proof", `{"proof":" \t"}`},
		{"case alias", strings.Replace(valid, "proof", "Proof", 1)},
		{"duplicate", strings.TrimSuffix(valid, "}") + `,"proof":"second"}`},
		{"escaped duplicate", strings.TrimSuffix(valid, "}") + `,"\u0070roof":"second"}`},
		{"actor field", strings.TrimSuffix(valid, "}") + `,"admin_actor_id":"forged"}`},
		{"target field", strings.TrimSuffix(valid, "}") + `,"target_user_id":"forged"}`},
		{"scope field", strings.TrimSuffix(valid, "}") + `,"service":"core"}`},
		{"trailing", valid + `{}`}, {"truncated", valid[:len(valid)-1]},
		{"invalid utf8", "\xff" + valid}, {"invalid string utf8", `{"proof":"` + "\xff" + `"}`},
		{"proof above cap", `{"proof":"` + strings.Repeat("x", 8193) + `"}`},
		{"envelope above cap", valid + strings.Repeat(" ", 16385-len(valid))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, store := mentorMutationRPCFixture(t)
			assertMentorMutationRPCReply(t, c, context.Background(), []byte(tc.body), `{"error":"invalid_proof"}`)
			if store.calls != 0 {
				t.Fatal("malformed envelope reached mutation store")
			}
		})
	}
	t.Run("exact envelope cap", func(t *testing.T) {
		c, store := mentorMutationRPCFixture(t)
		assertMentorMutationRPCReply(t, c, context.Background(), []byte(valid+strings.Repeat(" ", 16384-len(valid))), `{"ok":true}`)
		if store.writes != 1 {
			t.Fatal("exact bounded valid envelope denied")
		}
	})
}

func TestMentorRoleMutationRPCRejectsInvalidActualProofBeforeStore(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"wrong purpose", func(c map[string]any) { c["purpose"] = "AUTH_RBAC_KNOWLEDGE_GRAPH_REVIEW_PERMISSION_V1" }},
		{"wrong audience", func(c map[string]any) { c["aud"] = "other" }},
		{"wrong issuer", func(c map[string]any) { c["iss"] = "other" }},
		{"wrong role", func(c map[string]any) { c["role"] = "admin" }},
		{"wrong service", func(c map[string]any) { c["service"] = "core" }},
		{"foreign actor digest", func(c map[string]any) { c["sub"] = "00000000-0000-4000-8000-000000000a02" }},
		{"expired", func(c map[string]any) { c["iat"] = time.Now().Unix() - 40; c["exp"] = time.Now().Unix() - 10 }},
		{"future", func(c map[string]any) { c["iat"] = time.Now().Unix() + 60; c["exp"] = time.Now().Unix() + 90 }},
		{"extra field", func(c map[string]any) { c["admin"] = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, store := mentorMutationRPCFixture(t)
			claims := mentorMutationRPCClaims("APPROVE", 2)
			tc.edit(claims)
			assertMentorMutationRPCReply(t, c, context.Background(), mentorMutationRPCEnvelope(t, mentorMutationRPCSign(t, claims)), `{"error":"invalid_proof"}`)
			if store.calls != 0 {
				t.Fatal("invalid signed proof reached mutation store")
			}
		})
	}
	for _, tc := range []string{"wrong key", "tampered signature", "unsigned access token"} {
		t.Run(tc, func(t *testing.T) {
			c, store := mentorMutationRPCFixture(t)
			raw := mentorMutationRPCSign(t, mentorMutationRPCClaims("APPROVE", 2))
			switch tc {
			case "wrong key":
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatal("test key generation failed")
				}
				raw = mentorMutationRPCSignWithKey(t, key, mentorMutationRPCClaims("APPROVE", 2))
			case "tampered signature":
				parts := strings.Split(raw, ".")
				signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
				signature[0] ^= 1
				parts[2] = base64.RawURLEncoding.EncodeToString(signature)
				raw = strings.Join(parts, ".")
			case "unsigned access token":
				raw = "test-only-access-token"
			}
			assertMentorMutationRPCReply(t, c, context.Background(), mentorMutationRPCEnvelope(t, raw), `{"error":"invalid_proof"}`)
			if store.calls != 0 {
				t.Fatal("invalid proof reached store")
			}
		})
	}
}

func TestMentorRoleMutationRPCExactFailureTaxonomy(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"invalid proof", domain.ErrUnauthenticated, "invalid_proof"},
		{"invalid command", domain.ErrMentorRoleInvalidCommand, "invalid_proof"},
		{"forbidden", domain.ErrMentorRoleForbidden, "forbidden"},
		{"conflict", domain.ErrMentorRoleConflict, "conflict"},
		{"stale", domain.ErrMentorRoleStaleRevision, "conflict"},
		{"invalid snapshot", domain.ErrMentorRoleInvalidSnapshot, "unavailable"},
		{"unavailable", domain.ErrAuthorityUnavailable, "unavailable"},
		{"unknown", errors.New("private DB/token diagnostics"), "unavailable"},
		{"joined denial and failure", errors.Join(domain.ErrMentorRoleForbidden, errors.New("private outage")), "unavailable"},
		{"wrapped denial", fmt.Errorf("private dependency: %w", domain.ErrMentorRoleForbidden), "unavailable"},
		{"mixed conflict", errors.Join(domain.ErrMentorRoleConflict, domain.ErrAuthorityUnavailable), "unavailable"},
		{"mixed invalid proof", errors.Join(domain.ErrUnauthenticated, domain.ErrAuthorityUnavailable), "unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, store := mentorMutationRPCFixture(t)
			store.failure = tc.err
			raw := mentorMutationRPCSign(t, mentorMutationRPCClaims("APPROVE", 2))
			assertMentorMutationRPCReply(t, c, context.Background(), mentorMutationRPCEnvelope(t, raw), `{"error":"`+tc.want+`"}`)
			if store.calls != 1 || store.writes != 0 {
				t.Fatal("failure caused unexpected repeated application or write")
			}
		})
	}
	t.Run("inconsistent success is unavailable", func(t *testing.T) {
		c, store := mentorMutationRPCFixture(t)
		store.invalidResult = true
		assertMentorMutationRPCReply(t, c, context.Background(), mentorMutationRPCEnvelope(t, mentorMutationRPCSign(t, mentorMutationRPCClaims("APPROVE", 2))), `{"error":"unavailable"}`)
	})
}

func TestMentorRoleMutationRPCRejectsLocalFailuresWithoutBody(t *testing.T) {
	valid := mentorMutationRPCEnvelope(t, mentorMutationRPCSign(t, mentorMutationRPCClaims("APPROVE", 2)))
	for _, subject := range []string{"", "rbac.assign-role", "rbac.checkRoleScoped.v1", "rbac.*", "rbac.applyMentorRole.v1.extra", " rbac.applyMentorRole.v1"} {
		t.Run("subject "+subject, func(t *testing.T) {
			c, store := mentorMutationRPCFixture(t)
			body, err := c.Handle(context.Background(), subject, valid)
			if len(body) != 0 || err != domain.ErrAuthorityUnavailable || store.calls != 0 {
				t.Fatal("wrong subject did not fail before mutation")
			}
		})
	}
	for _, dependency := range []string{"nil handler", "nil mutation", "nil context", "cancelled context"} {
		t.Run(dependency, func(t *testing.T) {
			c, store := mentorMutationRPCFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch dependency {
			case "nil handler":
				c = nil
			case "nil mutation":
				c.Mutation = nil
			case "nil context":
				ctx = nil
			case "cancelled context":
				cancel()
			}
			body, err := c.Handle(ctx, MentorRoleMutationSubject, valid)
			if len(body) != 0 || err != domain.ErrAuthorityUnavailable || store.calls != 0 {
				t.Fatal("local failure did not fail closed before mutation")
			}
		})
	}
	for _, dependency := range []string{"verifier", "store", "unconfigured key"} {
		t.Run(dependency, func(t *testing.T) {
			c, store := mentorMutationRPCFixture(t)
			verifier, err := client.NewAuthMentorRoleProofVerifier("")
			if err != nil {
				t.Fatal("empty-key verifier construction failed")
			}
			switch dependency {
			case "verifier":
				c.Mutation = usecase.NewMentorRoleMutation(nil, store)
			case "store":
				encoded, _ := x509.MarshalPKIXPublicKey(&mentorMutationRPCKey(t).PublicKey)
				configured, _ := client.NewAuthMentorRoleProofVerifier(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded})))
				c.Mutation = usecase.NewMentorRoleMutation(configured, nil)
			case "unconfigured key":
				c.Mutation = usecase.NewMentorRoleMutation(verifier, store)
			}
			assertMentorMutationRPCReply(t, c, context.Background(), valid, `{"error":"unavailable"}`)
			if store.calls != 0 {
				t.Fatal("unavailable authority reached store")
			}
		})
	}
}

func TestMentorRoleMutationRPCBoundedContextAndCancellation(t *testing.T) {
	for _, earlier := range []bool{false, true} {
		t.Run(fmt.Sprint("earlier=", earlier), func(t *testing.T) {
			c, store := mentorMutationRPCFixture(t)
			ctx := context.Background()
			var expected time.Time
			if earlier {
				var cancel context.CancelFunc
				expected = time.Now().Add(2 * time.Second)
				ctx, cancel = context.WithDeadline(ctx, expected)
				defer cancel()
			}
			store.before = func(actual context.Context, _ domain.MentorRoleProof) {
				deadline, ok := actual.Deadline()
				if !ok || time.Until(deadline) > 5*time.Second || time.Until(deadline) <= 0 || (earlier && !deadline.Equal(expected)) {
					t.Fatal("operation deadline missing, extended or incorrectly bounded")
				}
			}
			assertMentorMutationRPCReply(t, c, ctx, mentorMutationRPCEnvelope(t, mentorMutationRPCSign(t, mentorMutationRPCClaims("APPROVE", 2))), `{"ok":true}`)
		})
	}
	for _, stage := range []string{"before store commit", "after committed mutation"} {
		t.Run(stage, func(t *testing.T) {
			c, store := mentorMutationRPCFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if stage == "before store commit" {
				store.before = func(context.Context, domain.MentorRoleProof) { cancel() }
			} else {
				store.afterCommit = cancel
			}
			body, err := c.Handle(ctx, MentorRoleMutationSubject, mentorMutationRPCEnvelope(t, mentorMutationRPCSign(t, mentorMutationRPCClaims("APPROVE", 2))))
			if len(body) != 0 || err != domain.ErrAuthorityUnavailable {
				t.Fatal("cancellation returned semantic result or successful ACK")
			}
			wantedWrites := 0
			if stage == "after committed mutation" {
				wantedWrites = 1
			}
			if store.writes != wantedWrites || store.calls != 1 {
				t.Fatal("cancellation asserted rollback or retried mutation")
			}
		})
	}
}

func TestMentorRoleMutationRPCLostCommitACKRequiresExplicitFreshReplay(t *testing.T) {
	c, store := mentorMutationRPCFixture(t)
	store.loseCommitACK = true
	claims := mentorMutationRPCClaims("APPROVE", 2)
	first := mentorMutationRPCSign(t, claims)
	assertMentorMutationRPCReply(t, c, context.Background(), mentorMutationRPCEnvelope(t, first), `{"error":"unavailable"}`)
	if store.calls != 1 || store.writes != 1 || len(store.receipts) != 1 {
		t.Fatal("uncertain commit was retried, lost or falsely rolled back")
	}
	claims["jti"] = "00000000-0000-4000-8000-000000000e02"
	second := mentorMutationRPCSign(t, claims)
	if first == second {
		t.Fatal("retry fixture did not supply a fresh proof")
	}
	assertMentorMutationRPCReply(t, c, context.Background(), mentorMutationRPCEnvelope(t, second), `{"ok":true}`)
	if store.calls != 2 || store.writes != 1 || len(store.receipts) != 1 || store.lastProof.JWTID != claims["jti"] {
		t.Fatal("explicit replay duplicated the durable command or cached old proof")
	}
}

func TestMentorRoleMutationRPCHistoricalApprovalACKDoesNotRevealOrRestoreRole(t *testing.T) {
	c, store := mentorMutationRPCFixture(t)
	approve := mentorMutationRPCClaims("APPROVE", 2)
	assertMentorMutationRPCReply(t, c, context.Background(), mentorMutationRPCEnvelope(t, mentorMutationRPCSign(t, approve)), `{"ok":true}`)
	assertMentorMutationRPCReply(t, c, context.Background(), mentorMutationRPCEnvelope(t, mentorMutationRPCSign(t, mentorMutationRPCClaims("SUSPEND", 4))), `{"ok":true}`)
	approve["jti"] = "00000000-0000-4000-8000-000000000e02"
	assertMentorMutationRPCReply(t, c, context.Background(), mentorMutationRPCEnvelope(t, mentorMutationRPCSign(t, approve)), `{"ok":true}`)
	if store.calls != 3 || store.writes != 2 || store.current.Active || !store.current.Suspended || len(store.receipts) != 2 {
		t.Fatal("historical approval ACK restored suspended role or rewrote history")
	}
	if !store.receipts[approve["request_id"].(string)].Applied.Active {
		t.Fatal("fixture lost historical/current distinction")
	}
}

func TestMentorRoleMutationRPCRevokeFirstRemainsTerminal(t *testing.T) {
	c, store := mentorMutationRPCFixture(t)
	assertMentorMutationRPCReply(t, c, context.Background(), mentorMutationRPCEnvelope(t, mentorMutationRPCSign(t, mentorMutationRPCClaims("SUSPEND", 3))), `{"ok":true}`)
	assertMentorMutationRPCReply(t, c, context.Background(), mentorMutationRPCEnvelope(t, mentorMutationRPCSign(t, mentorMutationRPCClaims("APPROVE", 2))), `{"error":"conflict"}`)
	if store.writes != 1 || store.current.Active || !store.current.Suspended {
		t.Fatal("late approval bypassed terminal suspension")
	}
}

func TestMentorRoleMutationRPCConcurrentReplayDoesNotDuplicateCommand(t *testing.T) {
	c, store := mentorMutationRPCFixture(t)
	body := mentorMutationRPCEnvelope(t, mentorMutationRPCSign(t, mentorMutationRPCClaims("APPROVE", 2)))
	var workers sync.WaitGroup
	failures := make(chan bool, 8)
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			reply, err := c.Handle(context.Background(), MentorRoleMutationSubject, body)
			failures <- err != nil || string(reply) != `{"ok":true}`
		}()
	}
	workers.Wait()
	close(failures)
	for failed := range failures {
		if failed {
			t.Fatal("concurrent authenticated replay failed")
		}
	}
	if store.calls != 8 || store.writes != 1 || store.rechecks != 24 || len(store.receipts) != 1 {
		t.Fatal("handler retried, cached authority or duplicated fixture command")
	}
}
