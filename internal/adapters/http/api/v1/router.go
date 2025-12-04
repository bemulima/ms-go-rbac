package v1

import (
	"net/http"

	"github.com/example/ms-rbac-service/internal/adapters/http/handlers"
)

// RegisterRoutes wires public/client endpoints onto a mux.
func RegisterRoutes(mux *http.ServeMux, h *handlers.APIHandlers) {
	mux.HandleFunc("/assign_role", h.HandleAssignRole)
	mux.HandleFunc("/get_role_by_user_id", h.HandleGetRoleByUserID)
	mux.HandleFunc("/get_permissions_by_user_id_for_role", h.HandleGetPermissionsByUserID)
	mux.HandleFunc("/check_role_by_user_id", h.HandleCheckRoleByUserID)
	mux.HandleFunc("/check_permission_by_user_id", h.HandleCheckPermissionByUserID)
}
