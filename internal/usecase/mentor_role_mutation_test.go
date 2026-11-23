package usecase

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/example/ms-rbac-service/internal/domain"
)

const mentorMutationRawProof = "test-only.exact-raw.bytes"

type mentorRoleTestContextKey struct{}

type mentorMutationVerifier struct {
	verify func(context.Context, string) (domain.MentorRoleProof, error)
	calls  int
}

func (v *mentorMutationVerifier) VerifyMentorRoleProof(ctx context.Context, raw string) (domain.MentorRoleProof, error) {
	v.calls++
	return v.verify(ctx, raw)
}

type mentorMutationStore struct {
	apply func(context.Context, domain.MentorRoleProof, domain.MentorRoleProofRevalidator) (domain.MentorRolePlan, error)
	calls int
}

func (s *mentorMutationStore) ApplyMentorRole(ctx context.Context, proof domain.MentorRoleProof, revalidate domain.MentorRoleProofRevalidator) (domain.MentorRolePlan, error) {
	s.calls++
	return s.apply(ctx, proof, revalidate)
}

func mentorMutationCommand(decision string, revision uint64) domain.MentorRoleCommand {
	request := "00000000-0000-4000-8000-000000000d01"
	if decision == domain.MentorRoleDecisionSuspend {
		request = "00000000-0000-4000-8000-000000000d02"
	}
	command := domain.MentorRoleCommand{
		Issuer: domain.MentorRoleProofIssuer, AdminID: "00000000-0000-4000-8000-000000000a01",
		TargetUserID: "00000000-0000-4000-8000-000000000b01", ApplicationID: "00000000-0000-4000-8000-000000000c01",
		ApplicationRevision: revision, Decision: decision, RequestID: request,
		Role: domain.MentorRole, Service: domain.MentorRoleService,
	}
	return mentorMutationCommandDigest(command)
}

func mentorMutationCommandDigest(command domain.MentorRoleCommand) domain.MentorRoleCommand {
	digest := sha256.Sum256([]byte(command.Decision + "|" + command.AdminID + "|" + command.ApplicationID + "|" + command.RequestID + "|" + strconv.FormatUint(command.ApplicationRevision-1, 10)))
	command.DecisionDigest = hex.EncodeToString(digest[:])
	return command
}

func mentorMutationProof(command domain.MentorRoleCommand) domain.MentorRoleProof {
	digest := sha256.Sum256([]byte(mentorMutationRawProof))
	return domain.MentorRoleProof{
		Command: command, JWTID: "00000000-0000-4000-8000-000000000e01",
		ProofDigest: hex.EncodeToString(digest[:]), IssuedAt: 2000000000, ExpiresAt: 2000000030,
	}
}

func mentorMutationPlan(t *testing.T, command domain.MentorRoleCommand) domain.MentorRolePlan {
	t.Helper()
	plan, err := domain.PlanMentorRoleCommand(command, domain.MentorRoleSnapshot{})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func mentorMutationStableVerifier(proof domain.MentorRoleProof) *mentorMutationVerifier {
	return &mentorMutationVerifier{verify: func(context.Context, string) (domain.MentorRoleProof, error) { return proof, nil }}
}

func TestMentorRoleMutationAdmitsBeforeStoreAndRevalidatesExactProof(t *testing.T) {
	for _, command := range []domain.MentorRoleCommand{
		mentorMutationCommand(domain.MentorRoleDecisionApprove, 2),
		mentorMutationCommand(domain.MentorRoleDecisionSuspend, 3),
		mentorMutationCommand(domain.MentorRoleDecisionSuspend, 4),
	} {
		t.Run(command.Decision+strconv.FormatUint(command.ApplicationRevision, 10), func(t *testing.T) {
			ctx := context.WithValue(context.Background(), mentorRoleTestContextKey{}, "invocation-value")
			proof := mentorMutationProof(command)
			wanted := mentorMutationPlan(t, command)
			var events []string
			verifier := &mentorMutationVerifier{verify: func(actual context.Context, raw string) (domain.MentorRoleProof, error) {
				if actual != ctx || raw != mentorMutationRawProof {
					t.Fatal("context or exact raw proof was replaced")
				}
				events = append(events, "verify")
				return proof, nil
			}}
			store := &mentorMutationStore{apply: func(actual context.Context, admitted domain.MentorRoleProof, check domain.MentorRoleProofRevalidator) (domain.MentorRolePlan, error) {
				events = append(events, "store")
				if actual != ctx || admitted != proof || check == nil {
					t.Fatal("atomic store did not receive exact admitted value/context and callback")
				}
				for range 3 {
					rechecked, err := check(actual)
					if err != nil || rechecked != proof {
						t.Fatal("per-boundary proof revalidation failed")
					}
				}
				return wanted, nil
			}}
			got, err := NewMentorRoleMutation(verifier, store).Apply(ctx, mentorMutationRawProof)
			if err != nil || got != wanted || store.calls != 1 || !reflect.DeepEqual(events, []string{"verify", "store", "verify", "verify", "verify"}) {
				t.Fatalf("admitted exact mutation failed: error=%v events=%v", err, events)
			}
		})
	}
}

func TestMentorRoleMutationReauthenticatesHistoricalReplay(t *testing.T) {
	command := mentorMutationCommand(domain.MentorRoleDecisionApprove, 2)
	proof := mentorMutationProof(command)
	rawProof := mentorMutationRawProof
	original := mentorMutationPlan(t, command)
	revoked := mentorMutationPlan(t, mentorMutationCommand(domain.MentorRoleDecisionSuspend, 4))
	wanted := domain.MentorRolePlan{Receipt: original.Receipt, Current: revoked.Current, Replay: true}
	verifier := mentorMutationStableVerifier(proof)
	store := &mentorMutationStore{apply: func(ctx context.Context, admitted domain.MentorRoleProof, check domain.MentorRoleProofRevalidator) (domain.MentorRolePlan, error) {
		if admitted != proof {
			t.Fatal("replay used an earlier admission value")
		}
		_, err := check(ctx)
		return wanted, err
	}}
	mutation := NewMentorRoleMutation(verifier, store)
	for i := range 2 {
		if i == 1 {
			rawProof += "-renewed"
			proof.JWTID = "00000000-0000-4000-8000-000000000e02"
			digest := sha256.Sum256([]byte(rawProof))
			proof.ProofDigest = hex.EncodeToString(digest[:])
			verifier.verify = func(_ context.Context, raw string) (domain.MentorRoleProof, error) {
				if raw != rawProof {
					t.Fatal("renewed proof bytes were not passed through")
				}
				return proof, nil
			}
		}
		got, err := mutation.Apply(context.Background(), rawProof)
		if err != nil || got != wanted || !got.Receipt.Applied.Active || got.Current.Active || !got.Current.Suspended || got.Write {
			t.Fatal("fresh authenticated replay lost historical/current distinction")
		}
	}
	if verifier.calls != 4 || store.calls != 2 {
		t.Fatal("replay cached admission")
	}
	verifier.verify = func(context.Context, string) (domain.MentorRoleProof, error) {
		return domain.MentorRoleProof{}, domain.ErrUnauthenticated
	}
	got, err := mutation.Apply(context.Background(), mentorMutationRawProof)
	if got != (domain.MentorRolePlan{}) || !errors.Is(err, domain.ErrUnauthenticated) || store.calls != 2 {
		t.Fatal("denied replay reached the store")
	}
}

func TestMentorRoleMutationRejectsInvalidContextBeforeDependencies(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, cancelled} {
		verifier := &mentorMutationVerifier{verify: func(context.Context, string) (domain.MentorRoleProof, error) {
			t.Fatal("invalid context reached verifier")
			return domain.MentorRoleProof{}, nil
		}}
		store := &mentorMutationStore{apply: func(context.Context, domain.MentorRoleProof, domain.MentorRoleProofRevalidator) (domain.MentorRolePlan, error) {
			t.Fatal("invalid context reached store")
			return domain.MentorRolePlan{}, nil
		}}
		got, err := NewMentorRoleMutation(verifier, store).Apply(ctx, mentorMutationRawProof)
		if got != (domain.MentorRolePlan{}) || !errors.Is(err, domain.ErrUnauthenticated) || verifier.calls != 0 || store.calls != 0 {
			t.Fatal("nil or cancelled context was not denied before dependencies")
		}
	}
}

func TestMentorRoleMutationRejectsMissingOrTypedNilDependencies(t *testing.T) {
	proof := mentorMutationProof(mentorMutationCommand(domain.MentorRoleDecisionApprove, 2))
	var nilVerifier *mentorMutationVerifier
	var nilStore *mentorMutationStore
	for _, mutation := range []*MentorRoleMutation{
		nil, {}, NewMentorRoleMutation(nil, nil), NewMentorRoleMutation(nilVerifier, nil),
		NewMentorRoleMutation(mentorMutationStableVerifier(proof), nil),
		NewMentorRoleMutation(mentorMutationStableVerifier(proof), nilStore),
	} {
		got, err := mutation.Apply(context.Background(), mentorMutationRawProof)
		if got != (domain.MentorRolePlan{}) || !errors.Is(err, domain.ErrAuthorityUnavailable) {
			t.Fatal("missing dependency did not fail closed")
		}
	}
}

func TestMentorRoleMutationRejectsVerifierFailureBeforeStoreAndSanitizesErrors(t *testing.T) {
	proof := mentorMutationProof(mentorMutationCommand(domain.MentorRoleDecisionApprove, 2))
	for _, tc := range []struct {
		name string
		err  error
		want error
	}{
		{"unauthenticated", domain.ErrUnauthenticated, domain.ErrUnauthenticated},
		{"unavailable", domain.ErrAuthorityUnavailable, domain.ErrAuthorityUnavailable},
		{"cancelled", context.Canceled, domain.ErrUnauthenticated},
		{"deadline", context.DeadlineExceeded, domain.ErrUnauthenticated},
		{"opaque", errors.New("private key or database diagnostics"), domain.ErrAuthorityUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verifier := &mentorMutationVerifier{verify: func(context.Context, string) (domain.MentorRoleProof, error) { return proof, tc.err }}
			store := &mentorMutationStore{apply: func(context.Context, domain.MentorRoleProof, domain.MentorRoleProofRevalidator) (domain.MentorRolePlan, error) {
				t.Fatal("failed admission reached a store")
				return domain.MentorRolePlan{}, nil
			}}
			got, err := NewMentorRoleMutation(verifier, store).Apply(context.Background(), mentorMutationRawProof)
			if got != (domain.MentorRolePlan{}) || err != tc.want || verifier.calls != 1 || store.calls != 0 {
				t.Fatal("failed admission leaked data or reached a store")
			}
		})
	}
}

func TestMentorRoleMutationRejectsMalformedOrWrongRawAdmissionBeforeStore(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*domain.MentorRoleProof)
	}{
		{"invalid command", func(p *domain.MentorRoleProof) { p.Command.Role = "admin" }},
		{"missing JTI", func(p *domain.MentorRoleProof) { p.JWTID = "" }},
		{"case aliased JTI", func(p *domain.MentorRoleProof) { p.JWTID = strings.ToUpper(p.JWTID) }},
		{"different raw digest", func(p *domain.MentorRoleProof) { p.ProofDigest = strings.Repeat("f", 64) }},
		{"missing raw digest", func(p *domain.MentorRoleProof) { p.ProofDigest = "" }},
		{"unsafe timestamp", func(p *domain.MentorRoleProof) { p.ExpiresAt = domain.MentorRoleProofMaxTimestamp + 1 }},
		{"long TTL", func(p *domain.MentorRoleProof) { p.ExpiresAt = p.IssuedAt + 31 }},
		{"nonpositive timestamp", func(p *domain.MentorRoleProof) { p.IssuedAt = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proof := mentorMutationProof(mentorMutationCommand(domain.MentorRoleDecisionApprove, 2))
			tc.edit(&proof)
			store := &mentorMutationStore{}
			got, err := NewMentorRoleMutation(mentorMutationStableVerifier(proof), store).Apply(context.Background(), mentorMutationRawProof)
			if got != (domain.MentorRolePlan{}) || err != domain.ErrUnauthenticated || store.calls != 0 {
				t.Fatal("malformed or differently bound admission reached store")
			}
		})
	}
}

func TestMentorRoleMutationRejectsCancellationDuringInitialVerification(t *testing.T) {
	proof := mentorMutationProof(mentorMutationCommand(domain.MentorRoleDecisionApprove, 2))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	verifier := &mentorMutationVerifier{verify: func(context.Context, string) (domain.MentorRoleProof, error) { cancel(); return proof, nil }}
	store := &mentorMutationStore{}
	got, err := NewMentorRoleMutation(verifier, store).Apply(ctx, mentorMutationRawProof)
	if got != (domain.MentorRolePlan{}) || err != domain.ErrUnauthenticated || store.calls != 0 {
		t.Fatal("cancelled admission reached store")
	}
}

func TestMentorRoleMutationRevalidationPinsEveryAdmittedField(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*domain.MentorRoleProof)
	}{
		{"issuer", func(p *domain.MentorRoleProof) { p.Command.Issuer = "other" }},
		{"actor", func(p *domain.MentorRoleProof) {
			p.Command.AdminID = "00000000-0000-4000-8000-000000000a02"
			p.Command = mentorMutationCommandDigest(p.Command)
		}},
		{"target", func(p *domain.MentorRoleProof) { p.Command.TargetUserID = "00000000-0000-4000-8000-000000000b02" }},
		{"application", func(p *domain.MentorRoleProof) {
			p.Command.ApplicationID = "00000000-0000-4000-8000-000000000c02"
			p.Command = mentorMutationCommandDigest(p.Command)
		}},
		{"revision", func(p *domain.MentorRoleProof) {
			p.Command.ApplicationRevision++
			p.Command = mentorMutationCommandDigest(p.Command)
		}},
		{"decision", func(p *domain.MentorRoleProof) {
			p.Command = mentorMutationCommand(domain.MentorRoleDecisionSuspend, 3)
		}},
		{"request", func(p *domain.MentorRoleProof) {
			p.Command.RequestID = "00000000-0000-4000-8000-000000000d03"
			p.Command = mentorMutationCommandDigest(p.Command)
		}},
		{"decision digest", func(p *domain.MentorRoleProof) { p.Command.DecisionDigest = strings.Repeat("f", 64) }},
		{"role", func(p *domain.MentorRoleProof) { p.Command.Role = "admin" }},
		{"service", func(p *domain.MentorRoleProof) { p.Command.Service = "core" }},
		{"JTI", func(p *domain.MentorRoleProof) { p.JWTID = "00000000-0000-4000-8000-000000000e02" }},
		{"proof digest", func(p *domain.MentorRoleProof) { p.ProofDigest = strings.Repeat("f", 64) }},
		{"issued at", func(p *domain.MentorRoleProof) { p.IssuedAt++ }},
		{"expires at", func(p *domain.MentorRoleProof) { p.ExpiresAt-- }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proof := mentorMutationProof(mentorMutationCommand(domain.MentorRoleDecisionApprove, 2))
			changed := proof
			tc.edit(&changed)
			calls := 0
			verifier := &mentorMutationVerifier{verify: func(_ context.Context, raw string) (domain.MentorRoleProof, error) {
				if raw != mentorMutationRawProof {
					t.Fatal("revalidation substituted proof bytes")
				}
				calls++
				if calls == 1 {
					return proof, nil
				}
				return changed, nil
			}}
			store := &mentorMutationStore{apply: func(ctx context.Context, _ domain.MentorRoleProof, check domain.MentorRoleProofRevalidator) (domain.MentorRolePlan, error) {
				got, err := check(ctx)
				if got != (domain.MentorRoleProof{}) || err != domain.ErrUnauthenticated {
					t.Fatal("different proof value survived revalidation")
				}
				return mentorMutationPlan(t, proof.Command), err
			}}
			got, err := NewMentorRoleMutation(verifier, store).Apply(context.Background(), mentorMutationRawProof)
			if got != (domain.MentorRolePlan{}) || err != domain.ErrUnauthenticated || calls != 2 || store.calls != 1 {
				t.Fatal("revalidation failure leaked a mutation result")
			}
		})
	}
}

func TestMentorRoleMutationRevalidationPreservesBothContextBoundaries(t *testing.T) {
	for _, mode := range []string{"nil transaction", "cancelled transaction", "cancelled original with live transaction", "cancel during reverify", "live child context"} {
		t.Run(mode, func(t *testing.T) {
			proof := mentorMutationProof(mentorMutationCommand(domain.MentorRoleDecisionApprove, 2))
			wanted := mentorMutationPlan(t, proof.Command)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var checkContext context.Context
			verifierCalls := 0
			verifier := &mentorMutationVerifier{verify: func(actual context.Context, raw string) (domain.MentorRoleProof, error) {
				verifierCalls++
				if raw != mentorMutationRawProof || (verifierCalls == 1 && actual != ctx) || (verifierCalls > 1 && actual != checkContext) {
					t.Fatal("context or bytes were replaced during revalidation")
				}
				if mode == "cancel during reverify" && verifierCalls > 1 {
					cancel()
				}
				return proof, nil
			}}
			store := &mentorMutationStore{apply: func(actual context.Context, admitted domain.MentorRoleProof, check domain.MentorRoleProofRevalidator) (domain.MentorRolePlan, error) {
				if actual != ctx || admitted != proof {
					t.Fatal("store invocation changed")
				}
				checkContext = ctx
				switch mode {
				case "nil transaction":
					checkContext = nil
				case "cancelled transaction":
					child, cancelChild := context.WithCancel(ctx)
					cancelChild()
					checkContext = child
				case "cancelled original with live transaction":
					cancel()
					checkContext = context.Background()
				case "live child context":
					checkContext = context.WithValue(ctx, mentorRoleTestContextKey{}, "transaction-value")
				}
				rechecked, err := check(checkContext)
				if mode == "live child context" {
					if err != nil || rechecked != proof {
						t.Fatal("valid child context was rejected")
					}
				} else if err != domain.ErrUnauthenticated || rechecked != (domain.MentorRoleProof{}) {
					t.Fatal("cancelled revalidation returned authority")
				}
				return wanted, err
			}}
			got, err := NewMentorRoleMutation(verifier, store).Apply(ctx, mentorMutationRawProof)
			if mode == "live child context" {
				if err != nil || got != wanted || verifierCalls != 2 {
					t.Fatal("live child context did not complete")
				}
			} else {
				expectedCalls := 1
				if mode == "cancel during reverify" {
					expectedCalls = 2
				}
				if err != domain.ErrUnauthenticated || got != (domain.MentorRolePlan{}) || verifierCalls != expectedCalls {
					t.Fatal("context failure did not abort at the right boundary")
				}
			}
		})
	}
}

func TestMentorRoleMutationRevalidationDenialAndDependencyFailureAbort(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want error
	}{
		{"expired while waiting", domain.ErrUnauthenticated, domain.ErrUnauthenticated},
		{"authority unavailable", domain.ErrAuthorityUnavailable, domain.ErrAuthorityUnavailable},
		{"opaque failure", errors.New("private verifier diagnostics"), domain.ErrAuthorityUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proof := mentorMutationProof(mentorMutationCommand(domain.MentorRoleDecisionApprove, 2))
			calls := 0
			verifier := &mentorMutationVerifier{verify: func(context.Context, string) (domain.MentorRoleProof, error) {
				calls++
				if calls == 1 {
					return proof, nil
				}
				return proof, tc.err
			}}
			store := &mentorMutationStore{apply: func(ctx context.Context, _ domain.MentorRoleProof, check domain.MentorRoleProofRevalidator) (domain.MentorRolePlan, error) {
				got, err := check(ctx)
				if got != (domain.MentorRoleProof{}) || err != tc.want {
					t.Fatal("failed revalidation leaked authority or diagnostics")
				}
				return mentorMutationPlan(t, proof.Command), err
			}}
			got, err := NewMentorRoleMutation(verifier, store).Apply(context.Background(), mentorMutationRawProof)
			if got != (domain.MentorRolePlan{}) || err != tc.want || calls != 2 {
				t.Fatal("failed revalidation was not returned safely")
			}
		})
	}
}

func TestMentorRoleMutationReturnsZeroForStoreErrorsWithoutPrivateDiagnostics(t *testing.T) {
	proof := mentorMutationProof(mentorMutationCommand(domain.MentorRoleDecisionApprove, 2))
	for _, failure := range []error{
		domain.ErrUnauthenticated, domain.ErrAuthorityUnavailable, domain.ErrMentorRoleForbidden,
		domain.ErrMentorRoleInvalidCommand, domain.ErrMentorRoleConflict, domain.ErrMentorRoleStaleRevision,
		domain.ErrMentorRoleInvalidSnapshot, context.Canceled, context.DeadlineExceeded, errors.New("private database detail"),
	} {
		store := &mentorMutationStore{apply: func(context.Context, domain.MentorRoleProof, domain.MentorRoleProofRevalidator) (domain.MentorRolePlan, error) {
			return mentorMutationPlan(t, proof.Command), failure
		}}
		got, err := NewMentorRoleMutation(mentorMutationStableVerifier(proof), store).Apply(context.Background(), mentorMutationRawProof)
		wanted := failure
		if failure == context.Canceled || failure == context.DeadlineExceeded {
			wanted = domain.ErrUnauthenticated
		} else if failure.Error() == "private database detail" {
			wanted = domain.ErrAuthorityUnavailable
		}
		if got != (domain.MentorRolePlan{}) || err != wanted {
			t.Fatal("store failure returned receipt data or private diagnostics")
		}
	}
}

func TestMentorRoleMutationRejectsMalformedOrCrossBindingStoreSuccess(t *testing.T) {
	proof := mentorMutationProof(mentorMutationCommand(domain.MentorRoleDecisionApprove, 2))
	for _, tc := range []struct {
		name string
		edit func(*domain.MentorRolePlan)
	}{
		{"zero result", func(p *domain.MentorRolePlan) { *p = domain.MentorRolePlan{} }},
		{"both flags", func(p *domain.MentorRolePlan) { p.Replay = true }},
		{"neither flag", func(p *domain.MentorRolePlan) { p.Write = false }},
		{"receipt target", func(p *domain.MentorRolePlan) {
			command := proof.Command
			command.TargetUserID = "00000000-0000-4000-8000-000000000b02"
			*p = mentorMutationPlan(t, command)
		}},
		{"receipt actor", func(p *domain.MentorRolePlan) {
			command := proof.Command
			command.AdminID = "00000000-0000-4000-8000-000000000a02"
			*p = mentorMutationPlan(t, mentorMutationCommandDigest(command))
		}},
		{"receipt request", func(p *domain.MentorRolePlan) {
			command := proof.Command
			command.RequestID = "00000000-0000-4000-8000-000000000d03"
			*p = mentorMutationPlan(t, mentorMutationCommandDigest(command))
		}},
		{"historical state corrupted", func(p *domain.MentorRolePlan) { p.Receipt.Applied.Active = false }},
		{"current state corrupted", func(p *domain.MentorRolePlan) { p.Current.Suspended = true }},
		{"current other application", func(p *domain.MentorRolePlan) {
			command := mentorMutationCommand(domain.MentorRoleDecisionSuspend, 4)
			command.ApplicationID = "00000000-0000-4000-8000-000000000c02"
			p.Current = mentorMutationPlan(t, mentorMutationCommandDigest(command)).Current
			p.Write = false
			p.Replay = true
		}},
		{"write with historical current", func(p *domain.MentorRolePlan) {
			p.Current = mentorMutationPlan(t, mentorMutationCommand(domain.MentorRoleDecisionSuspend, 4)).Current
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			malformed := mentorMutationPlan(t, proof.Command)
			tc.edit(&malformed)
			store := &mentorMutationStore{apply: func(context.Context, domain.MentorRoleProof, domain.MentorRoleProofRevalidator) (domain.MentorRolePlan, error) {
				return malformed, nil
			}}
			got, err := NewMentorRoleMutation(mentorMutationStableVerifier(proof), store).Apply(context.Background(), mentorMutationRawProof)
			if got != (domain.MentorRolePlan{}) || err != domain.ErrMentorRoleInvalidSnapshot {
				t.Fatal("malformed/cross-bound success was returned as a receipt")
			}
		})
	}
}

func TestMentorRoleMutationDoesNotReauthenticateAfterStoreCommitted(t *testing.T) {
	proof := mentorMutationProof(mentorMutationCommand(domain.MentorRoleDecisionApprove, 2))
	wanted := mentorMutationPlan(t, proof.Command)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	verifier := mentorMutationStableVerifier(proof)
	store := &mentorMutationStore{apply: func(actual context.Context, _ domain.MentorRoleProof, check domain.MentorRoleProofRevalidator) (domain.MentorRolePlan, error) {
		if _, err := check(actual); err != nil {
			return domain.MentorRolePlan{}, err
		}
		// The adapter reports a completed commit. Cancellation after that point
		// must not become an apparent rolled-back authentication failure.
		cancel()
		return wanted, nil
	}}
	got, err := NewMentorRoleMutation(verifier, store).Apply(ctx, mentorMutationRawProof)
	if err != nil || got != wanted || verifier.calls != 2 {
		t.Fatal("post-commit cancellation was misreported as a failed mutation")
	}
}
