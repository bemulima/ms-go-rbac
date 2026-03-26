package v1

import (
	"net/http"

	"github.com/example/ms-rbac-service/internal/adapters/http/handlers"
)

// RegisterRoutes wires public/client endpoints onto a mux.
func RegisterRoutes(mux *http.ServeMux, h *handlers.APIHandlers) {
	mux.HandleFunc("/principal-role/update", h.PrincipalRole.Update)
	mux.HandleFunc("/principal-role/get", h.PrincipalRole.Get)
	mux.HandleFunc("/principal-permission/list", h.PrincipalPermission.List)
	mux.HandleFunc("/principal-role/get-by-role", h.PrincipalRole.GetByRole)
	mux.HandleFunc("/principal-permission/get-by-permission", h.PrincipalPermission.GetByPermission)
}
