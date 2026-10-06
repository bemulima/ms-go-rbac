package domain

import (
	"encoding/hex"
	"errors"
	"strings"
)

var (
	ErrUnauthenticated      = errors.New("authoritative access identity required")
	ErrAuthorityUnavailable = errors.New("identity authority unavailable")
)

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
