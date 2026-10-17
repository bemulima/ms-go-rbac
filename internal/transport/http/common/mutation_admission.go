package common

import (
	"errors"
	"net/http"
	"strings"

	"github.com/example/ms-rbac-service/internal/domain"
	"github.com/example/ms-rbac-service/internal/usecase"
)

// AdmitMutation runs before payload processing, usecase reads, replay or writes.
func AdmitMutation(w http.ResponseWriter, r *http.Request, admission *usecase.MutationAdmission) bool {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		WriteError(w, http.StatusUnauthorized, "authoritative access identity required")
		return false
	}
	parts := strings.Fields(values[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || !validBearer(parts[1]) {
		WriteError(w, http.StatusUnauthorized, "authoritative access identity required")
		return false
	}
	err := admission.Admit(r.Context(), parts[1])
	if err == nil {
		return true
	}
	switch {
	case errors.Is(err, domain.ErrUnauthenticated):
		WriteError(w, http.StatusUnauthorized, "authoritative access identity required")
	case errors.Is(err, domain.ErrMutationForbidden):
		WriteError(w, http.StatusForbidden, "mutation grant is not approved")
	default:
		WriteError(w, http.StatusServiceUnavailable, "identity authority unavailable")
	}
	return false
}

func validBearer(token string) bool {
	if token == "" || len(token) > 16<<10 {
		return false
	}
	padding := false
	for _, ch := range token {
		if ch == '=' {
			padding = true
			continue
		}
		if padding || !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || strings.ContainsRune("-._~+/", ch)) {
			return false
		}
	}
	return token[0] != '='
}
