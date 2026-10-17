package domain

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
)

var (
	ErrUnauthenticated      = errors.New("authoritative access identity required")
	ErrMutationForbidden    = errors.New("mutation grant is not approved")
	ErrAuthorityUnavailable = errors.New("identity authority unavailable")
)

// VerifiedActor is identity established by the configured Auth authority.
// Identity alone does not establish a grant to mutate RBAC data.
type VerifiedActor struct {
	PrincipalID string
}

type AccessIdentityVerifier interface {
	VerifyAccessToken(context.Context, string) (VerifiedActor, error)
}

// ValidPrincipalID requires the canonical non-nil UUID representation.
func ValidPrincipalID(id string) bool {
	if len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		return false
	}
	compact := strings.ReplaceAll(id, "-", "")
	decoded, err := hex.DecodeString(compact)
	if err != nil || len(decoded) != 16 {
		return false
	}
	for _, b := range decoded {
		if b != 0 {
			return true
		}
	}
	return false
}
