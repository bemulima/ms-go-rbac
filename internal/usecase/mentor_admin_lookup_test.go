package usecase

import (
	"context"
	"errors"
	"testing"

	"github.com/example/ms-rbac-service/internal/domain"
)

const mentorAdminLookupActor = "00000000-0000-4000-8000-000000000a01"

type mentorAdminRoleFixture struct {
	role   string
	err    error
	calls  int
	actor  string
	cancel context.CancelFunc
}

func (fixture *mentorAdminRoleFixture) GetDefaultRole(ctx context.Context, actor string) (string, error) {
	fixture.calls++
	fixture.actor = actor
	if fixture.cancel != nil {
		fixture.cancel()
	}
	return fixture.role, fixture.err
}

func TestMentorCanonicalAdminLookupReadsOnlyExactRoleWithoutCaching(t *testing.T) {
	fixture := &mentorAdminRoleFixture{role: "admin"}
	lookup := NewMentorCanonicalAdminLookup(fixture)
	for _, tc := range []struct {
		role  string
		allow bool
	}{
		{"admin", true}, {"student", false}, {"", false}, {"reviewer", false},
		{"Admin", false}, {" admin", false}, {"admin ", false}, {"superadmin", false}, {"admin", true},
	} {
		fixture.role = tc.role
		before := fixture.calls
		allowed, err := lookup.Check(context.Background(), mentorAdminLookupActor)
		if err != nil || allowed != tc.allow || fixture.calls != before+1 || fixture.actor != mentorAdminLookupActor {
			t.Fatalf("current exact role lookup failed for %q: allow=%v err=%v calls=%d", tc.role, allowed, err, fixture.calls)
		}
	}
}

func TestMentorCanonicalAdminLookupDeniesInvalidIdentityAndDependencies(t *testing.T) {
	fixture := &mentorAdminRoleFixture{role: "admin"}
	lookup := NewMentorCanonicalAdminLookup(fixture)
	for _, actor := range []string{"", "not-a-uuid", "00000000-0000-0000-0000-000000000000", "00000000-0000-4000-8000-000000000A01"} {
		if allowed, err := lookup.Check(context.Background(), actor); allowed || !errors.Is(err, domain.ErrUnauthenticated) || fixture.calls != 0 {
			t.Fatal("invalid actor reached canonical role store or was admitted")
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, cancelled} {
		if allowed, err := lookup.Check(ctx, mentorAdminLookupActor); allowed || !errors.Is(err, domain.ErrUnauthenticated) || fixture.calls != 0 {
			t.Fatal("invalid context reached canonical role store")
		}
	}
	var typedNil *mentorAdminRoleFixture
	for _, unavailable := range []*MentorCanonicalAdminLookup{nil, {}, NewMentorCanonicalAdminLookup(nil), NewMentorCanonicalAdminLookup(typedNil)} {
		if allowed, err := unavailable.Check(context.Background(), mentorAdminLookupActor); allowed || !errors.Is(err, domain.ErrAuthorityUnavailable) {
			t.Fatal("missing role reader did not fail closed")
		}
	}
	for _, failure := range []error{domain.ErrAmbiguousPrincipalRole, errors.New("private database failure detail")} {
		fixture.err = failure
		if allowed, err := lookup.Check(context.Background(), mentorAdminLookupActor); allowed || !errors.Is(err, domain.ErrAuthorityUnavailable) {
			t.Fatal("failed or ambiguous canonical role read did not deny")
		}
	}
	fixture.err = nil
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fixture.cancel = cancel
	if allowed, err := lookup.Check(ctx, mentorAdminLookupActor); allowed || !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatal("mid-read cancellation admitted an actor")
	}
}
