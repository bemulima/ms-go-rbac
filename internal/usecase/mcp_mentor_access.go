package usecase

import (
	"context"
	"strings"

	"github.com/example/ms-rbac-service/internal/domain"
)

type MCPMentorAccessUsecase struct{ Reader domain.MCPMentorAccessReader }

func (u MCPMentorAccessUsecase) ReadMCPMentorAccess(ctx context.Context, subject string) (domain.MCPMentorAccess, error) {
	if ctx == nil || ctx.Err() != nil || !domain.ValidPrincipalID(subject) || subject != strings.ToLower(subject) {
		return domain.MCPMentorAccess{}, domain.ErrUnauthenticated
	}
	if u.Reader == nil {
		return domain.MCPMentorAccess{}, domain.ErrAuthorityUnavailable
	}
	result, err := u.Reader.ReadMCPMentorAccess(ctx, subject)
	if err != nil || ctx.Err() != nil || (result.Allowed && !result.Active) {
		return domain.MCPMentorAccess{}, domain.ErrAuthorityUnavailable
	}
	return result, nil
}
