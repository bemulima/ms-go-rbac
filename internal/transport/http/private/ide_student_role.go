package private

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/example/ms-rbac-service/internal/domain"
)

// IDEStudentRoleOwner reads only the canonical RBAC default scope.
// Never use PrincipalRoleUsecase.Get: its legacy fallback may select
// another tenant/resource scope when the default binding is absent.
type IDEStudentRoleOwner interface {
	GetDefaultRole(context.Context, string) (string, error)
}

// IDEStudentRoleHandler is a separate, default-OFF, read-only capability
// exclusively for the Practice Runtime IDE28 GUIDED coordinator.
type IDEStudentRoleHandler struct {
	Enabled bool
	Token   string
	Roles   IDEStudentRoleOwner
}

func RegisterIDEStudentRoleRoutes(mux *http.ServeMux, handler *IDEStudentRoleHandler) {
	if mux == nil || handler == nil || !handler.Enabled ||
		handler.Roles == nil || !validIDEStudentRoleCapability(handler.Token) {
		return
	}
	mux.HandleFunc("GET /ide/v1/principals/{studentID}/student-role", handler.read)
}

func (handler *IDEStudentRoleHandler) read(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "private, no-store")
	tokens := r.Header.Values("X-Internal-Token")
	services := r.Header.Values("X-Service-Name")
	if r.Method != http.MethodGet || !validIDEStudentRoleCapability(handler.Token) ||
		len(tokens) != 1 || len(services) != 1 ||
		subtle.ConstantTimeCompare([]byte(tokens[0]), []byte(handler.Token)) != 1 ||
		services[0] != "ms-go-practice-runtime" ||
		len(r.Header.Values("Authorization")) != 0 ||
		len(r.Header.Values("Cookie")) != 0 ||
		len(r.Header.Values("X-User-Role")) != 0 ||
		len(r.Header.Values("X-Verified-Student-Role")) != 0 ||
		r.URL.RawQuery != "" || r.ContentLength != 0 ||
		len(r.TransferEncoding) != 0 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	studentID := r.PathValue("studentID")
	if !domain.ValidPrincipalID(studentID) || strings.ToLower(studentID) != studentID {
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}
	role, err := handler.Roles.GetDefaultRole(r.Context(), studentID)
	if err != nil {
		http.Error(w, "role_unavailable", http.StatusServiceUnavailable)
		return
	}
	switch role {
	case "student", "STUDENT":
		role = "STUDENT"
	case "student_pro", "STUDENT_PRO":
		role = "STUDENT_PRO"
	default:
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Schema    string `json:"schema"`
		StudentID string `json:"student_id"`
		Role      string `json:"role"`
	}{"rbac-ide-student-role.v1", studentID, role})
}

func validIDEStudentRoleCapability(token string) bool {
	if len(token) < 32 || len(token) > 4096 {
		return false
	}
	lower := strings.ToLower(token)
	for _, bad := range []string{"change-me", "placeholder", "replace-me", "example", "${"} {
		if strings.Contains(lower, bad) {
			return false
		}
	}
	for _, ch := range token {
		if ch < 33 || ch > 126 {
			return false
		}
	}
	return true
}
