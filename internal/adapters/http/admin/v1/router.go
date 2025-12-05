package v1

import (
	"net/http"

	"github.com/example/ms-rbac-service/internal/adapters/http/handlers"
)

// RegisterRoutes wires admin endpoints onto a mux.
func RegisterRoutes(mux *http.ServeMux, h *handlers.AdminHandlers) {
	mux.HandleFunc("/service", h.HandleService)
	mux.HandleFunc("/service/", h.HandleService)
	mux.HandleFunc("/service-list", h.HandleServiceList)
	mux.HandleFunc("/role", h.HandleRole)
	mux.HandleFunc("/role/", h.HandleRole)
	mux.HandleFunc("/role-list", h.HandleRoleList)
	mux.HandleFunc("/permission", h.HandlePermission)
	mux.HandleFunc("/permission/", h.HandlePermission)
	mux.HandleFunc("/permission-list", h.HandlePermissionList)
	mux.HandleFunc("/role-permission", h.HandleRolePermission)
}
