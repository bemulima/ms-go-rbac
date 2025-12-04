package v1

import (
	"net/http"

	"github.com/example/ms-rbac-service/internal/adapters/http/handlers"
)

// RegisterRoutes wires admin endpoints onto a mux.
func RegisterRoutes(mux *http.ServeMux, h *handlers.AdminHandlers) {
	mux.HandleFunc("/admin/service", h.HandleService)
	mux.HandleFunc("/admin/service/", h.HandleService)
	mux.HandleFunc("/admin/service-list", h.HandleServiceList)
	mux.HandleFunc("/admin/role", h.HandleRole)
	mux.HandleFunc("/admin/role/", h.HandleRole)
	mux.HandleFunc("/admin/role-list", h.HandleRoleList)
	mux.HandleFunc("/admin/permission", h.HandlePermission)
	mux.HandleFunc("/admin/permission/", h.HandlePermission)
	mux.HandleFunc("/admin/permission-list", h.HandlePermissionList)
	mux.HandleFunc("/admin/role-permission", h.HandleRolePermission)
}
