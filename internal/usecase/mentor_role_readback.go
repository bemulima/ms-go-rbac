package usecase

import (
	"context"
	"reflect"

	"github.com/example/ms-rbac-service/internal/domain"
)

type MentorRoleReadbackLookup struct {
	reader domain.MentorRoleReadbackReader
}

func NewMentorRoleReadbackLookup(reader domain.MentorRoleReadbackReader) *MentorRoleReadbackLookup {
	return &MentorRoleReadbackLookup{reader: reader}
}

func (lookup *MentorRoleReadbackLookup) Check(ctx context.Context, command domain.MentorRoleCommand) (domain.MentorRoleReadbackResult, error) {
	if lookup == nil || ctx == nil || ctx.Err() != nil || !domain.ValidMentorRoleCommand(command) || missingMentorReadbackReader(lookup.reader) {
		return domain.MentorRoleReadbackResult{}, domain.ErrAuthorityUnavailable
	}
	result, err := lookup.reader.ReadMentorRole(ctx, command)
	if err != nil || ctx.Err() != nil || !domain.ValidMentorRoleReadbackResult(command, result) {
		return domain.MentorRoleReadbackResult{}, domain.ErrAuthorityUnavailable
	}
	return result, nil
}

func missingMentorReadbackReader(reader domain.MentorRoleReadbackReader) bool {
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

var _ domain.MentorRoleReadbackChecker = (*MentorRoleReadbackLookup)(nil)
