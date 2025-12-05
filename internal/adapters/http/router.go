package http

import (
	"net/http"

	adminv1 "github.com/example/ms-rbac-service/internal/adapters/http/admin/v1"
	apiv1 "github.com/example/ms-rbac-service/internal/adapters/http/api/v1"
	"github.com/example/ms-rbac-service/internal/adapters/http/handlers"
)

type Router struct {
	adminHandlers *handlers.AdminHandlers
	apiHandlers   *handlers.APIHandlers
}

func NewRouter(adminHandlers *handlers.AdminHandlers, apiHandlers *handlers.APIHandlers) *Router {
	return &Router{adminHandlers: adminHandlers, apiHandlers: apiHandlers}
}

func (r *Router) Handler() http.Handler {
	mux := http.NewServeMux()

	apiMux := http.NewServeMux()
	apiv1.RegisterRoutes(apiMux, r.apiHandlers)
	mux.Handle("/api/v1/", http.StripPrefix("/api/v1", apiMux))

	adminMux := http.NewServeMux()
	adminv1.RegisterRoutes(adminMux, r.adminHandlers)
	mux.Handle("/admin/v1/", http.StripPrefix("/admin/v1", adminMux))

	return mux
}
