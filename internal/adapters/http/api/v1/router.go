package v1

import (
	"net/http"

	"github.com/example/ms-rbac-service/internal/adapters/http/handlers"
)

// RegisterRoutes wires public/client endpoints onto a mux.
func RegisterRoutes(mux *http.ServeMux, h *handlers.APIHandlers) {
	mux.HandleFunc("/assign_role", h.PrincipalRole.Update)
	mux.HandleFunc("/get_role_by_user_id", h.PrincipalRole.Get)
	mux.HandleFunc("/get_permissions_by_user_id_for_role", h.PrincipalPermission.List)
	mux.HandleFunc("/check_role_by_user_id", h.PrincipalRole.GetByRole)
	mux.HandleFunc("/check_permission_by_user_id", h.PrincipalPermission.GetByPermission)
}
