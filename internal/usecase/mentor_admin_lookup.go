package usecase

import (
	"context"
	"reflect"
	"strings"

	"github.com/example/ms-rbac-service/internal/domain"
)

// MentorCanonicalAdminLookup is a read-only point-in-time check, not a role
// grant or a replacement for the future atomic mutation-time Admin recheck.
type MentorCanonicalAdminLookup struct {
	roles domain.MentorCanonicalAdminRoleReader
}

func NewMentorCanonicalAdminLookup(roles domain.MentorCanonicalAdminRoleReader) *MentorCanonicalAdminLookup {
	return &MentorCanonicalAdminLookup{roles: roles}
}

func (lookup *MentorCanonicalAdminLookup) Check(ctx context.Context, actorID string) (bool, error) {
	if ctx == nil || ctx.Err() != nil || !domain.ValidPrincipalID(actorID) || actorID != strings.ToLower(actorID) {
		return false, domain.ErrUnauthenticated
	}
	if lookup == nil || missingMentorAdminRoleReader(lookup.roles) {
		return false, domain.ErrAuthorityUnavailable
	}
	role, err := lookup.roles.GetDefaultRole(ctx, actorID)
	if ctx.Err() != nil {
		return false, domain.ErrUnauthenticated
	}
	if err != nil {
		return false, domain.ErrAuthorityUnavailable
	}
	// The repository owns uniqueness and the exact canonical tuple. Never use
	// its legacy any-scope Get method or normalize unexpected stored role keys.
	return role == "admin", nil
}

func missingMentorAdminRoleReader(reader domain.MentorCanonicalAdminRoleReader) bool {
	if reader == nil {
		return true
	}
	value := reflect.ValueOf(reader)
	switch value.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return value.IsNil()
	default:
		return false
	}
}
