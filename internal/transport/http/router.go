package http

import (
	"net/http"

	adminv1 "github.com/example/ms-rbac-service/internal/transport/http/admin/v1"
	adminhandlers "github.com/example/ms-rbac-service/internal/transport/http/admin/v1/handlers"
	apiv1 "github.com/example/ms-rbac-service/internal/transport/http/api/v1"
	apihandlers "github.com/example/ms-rbac-service/internal/transport/http/api/v1/handlers"
	private "github.com/example/ms-rbac-service/internal/transport/http/private"
)

type Router struct {
	adminHandlers *adminhandlers.AdminHandlers
	apiHandlers   *apihandlers.APIHandlers
}

func NewRouter(adminHandlers *adminhandlers.AdminHandlers, apiHandlers *apihandlers.APIHandlers) *Router {
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

	privateMux := http.NewServeMux()
	private.RegisterRoutes(privateMux)
	mux.Handle("/private/", http.StripPrefix("/private", privateMux))

	return mux
}
