package v1

import (
	"net/http"

	"github.com/example/ms-rbac-service/internal/adapters/http/handlers"
)

// RegisterRoutes wires admin endpoints onto a mux.
func RegisterRoutes(mux *http.ServeMux, h *handlers.AdminHandlers) {
	mux.HandleFunc("/service", h.Service.Create)
	mux.HandleFunc("/service/", methodMux(map[string]http.HandlerFunc{
		http.MethodGet: h.Service.Get,
		http.MethodPut: h.Service.Update,
	}))
	mux.HandleFunc("/service-list", h.Service.List)

	mux.HandleFunc("/role", h.Role.Create)
	mux.HandleFunc("/role/", methodMux(map[string]http.HandlerFunc{
		http.MethodGet: h.Role.Get,
		http.MethodPut: h.Role.Update,
	}))
	mux.HandleFunc("/role-list", h.Role.List)

	mux.HandleFunc("/permission", h.Permission.Create)
	mux.HandleFunc("/permission/", methodMux(map[string]http.HandlerFunc{
		http.MethodGet: h.Permission.Get,
		http.MethodPut: h.Permission.Update,
	}))
	mux.HandleFunc("/permission-list", h.Permission.List)

	mux.HandleFunc("/role-permission", h.RolePermission.Create)
}

func methodMux(handlers map[string]http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h, ok := handlers[r.Method]
		if !ok {
			http.NotFound(w, r)
			return
		}
		h(w, r)
	}
}
