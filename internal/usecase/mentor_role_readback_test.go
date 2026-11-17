package usecase

import (
	"context"
	"errors"
	"testing"

	"github.com/example/ms-rbac-service/internal/domain"
)

type mentorReadbackReaderFixture struct {
	calls int
	read  func(context.Context, domain.MentorRoleCommand) (domain.MentorRoleReadbackResult, error)
}

func (f *mentorReadbackReaderFixture) ReadMentorRole(ctx context.Context, command domain.MentorRoleCommand) (domain.MentorRoleReadbackResult, error) {
	f.calls++
	return f.read(ctx, command)
}

func TestMentorRoleReadbackLookupPreservesExactCommandAndSemanticAbsence(t *testing.T) {
	for _, c := range []domain.MentorRoleCommand{mentorMutationCommand("APPROVE", 2), mentorMutationCommand("SUSPEND", 3), mentorMutationCommand("SUSPEND", 4)} {
		for _, confirmed := range []bool{false, true} {
			t.Run(c.Decision+string(rune('0'+c.ApplicationRevision))+map[bool]string{false: " absent", true: " confirmed"}[confirmed], func(t *testing.T) {
				ctx := context.WithValue(context.Background(), struct{}{}, "invocation")
				want := domain.MentorRoleReadbackResult{Confirmed: confirmed, Active: confirmed && c.Decision == "APPROVE"}
				reader := &mentorReadbackReaderFixture{read: func(actual context.Context, got domain.MentorRoleCommand) (domain.MentorRoleReadbackResult, error) {
					if actual != ctx || got != c {
						t.Fatal("replaced context or exact binding")
					}
					return want, nil
				}}
				got, err := NewMentorRoleReadbackLookup(reader).Check(ctx, c)
				if err != nil || got != want || reader.calls != 1 {
					t.Fatalf("lookup failed: result=%v error=%v calls=%d", got, err, reader.calls)
				}
			})
		}
	}
}

func TestMentorRoleReadbackLookupRejectsInvalidCommandBeforeReader(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*domain.MentorRoleCommand)
	}{
		{"admin scope", func(c *domain.MentorRoleCommand) { c.Role = "admin" }},
		{"other service", func(c *domain.MentorRoleCommand) { c.Service = "core" }},
		{"digest", func(c *domain.MentorRoleCommand) { c.DecisionDigest = "" }},
		{"revision", func(c *domain.MentorRoleCommand) { c.ApplicationRevision = 7 }},
		{"issuer", func(c *domain.MentorRoleCommand) { c.Issuer = "ms-go-mentor" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := mentorMutationCommand("APPROVE", 2)
			tc.edit(&c)
			reader := &mentorReadbackReaderFixture{read: func(context.Context, domain.MentorRoleCommand) (domain.MentorRoleReadbackResult, error) {
				t.Fatal("invalid command reached reader")
				return domain.MentorRoleReadbackResult{}, nil
			}}
			got, err := NewMentorRoleReadbackLookup(reader).Check(context.Background(), c)
			if !errors.Is(err, domain.ErrAuthorityUnavailable) || got != (domain.MentorRoleReadbackResult{}) || reader.calls != 0 {
				t.Fatalf("invalid command did not fail closed: %v", err)
			}
		})
	}
}

func TestMentorRoleReadbackLookupSanitizesFailuresAndInvalidAnswers(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result domain.MentorRoleReadbackResult
		err    error
	}{
		{"dependency", domain.MentorRoleReadbackResult{}, errors.New("private diagnostic")},
		{"partial success with failure", domain.MentorRoleReadbackResult{Confirmed: true, Active: true}, errors.New("private diagnostic")},
		{"unconfirmed active", domain.MentorRoleReadbackResult{Confirmed: false, Active: true}, nil},
		{"inactive approval", domain.MentorRoleReadbackResult{Confirmed: true, Active: false}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader := &mentorReadbackReaderFixture{read: func(context.Context, domain.MentorRoleCommand) (domain.MentorRoleReadbackResult, error) {
				return tc.result, tc.err
			}}
			got, err := NewMentorRoleReadbackLookup(reader).Check(context.Background(), mentorMutationCommand("APPROVE", 2))
			if err != domain.ErrAuthorityUnavailable || got != (domain.MentorRoleReadbackResult{}) {
				t.Fatalf("unsafe result or diagnostic: %v %v", got, err)
			}
		})
	}
}

func TestMentorRoleReadbackLookupCancellationAndMissingDependencies(t *testing.T) {
	c := mentorMutationCommand("APPROVE", 2)
	for _, tc := range []struct {
		name   string
		lookup *MentorRoleReadbackLookup
		ctx    context.Context
	}{
		{"nil lookup", nil, context.Background()},
		{"nil reader", NewMentorRoleReadbackLookup(nil), context.Background()},
		{"typed nil reader", NewMentorRoleReadbackLookup((*mentorReadbackReaderFixture)(nil)), context.Background()},
		{"nil context", NewMentorRoleReadbackLookup(nil), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.lookup.Check(tc.ctx, c)
			if err != domain.ErrAuthorityUnavailable || got != (domain.MentorRoleReadbackResult{}) {
				t.Fatalf("unsafe missing dependency: %v", err)
			}
		})
	}
	for _, during := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancelled before", true: "cancelled during"}[during], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reader := &mentorReadbackReaderFixture{read: func(context.Context, domain.MentorRoleCommand) (domain.MentorRoleReadbackResult, error) {
				cancel()
				return domain.MentorRoleReadbackResult{Confirmed: true, Active: true}, nil
			}}
			if !during {
				cancel()
			}
			got, err := NewMentorRoleReadbackLookup(reader).Check(ctx, c)
			if err != domain.ErrAuthorityUnavailable || got != (domain.MentorRoleReadbackResult{}) || (!during && reader.calls != 0) {
				t.Fatalf("cancelled read exposed result: %v", err)
			}
		})
	}
}
