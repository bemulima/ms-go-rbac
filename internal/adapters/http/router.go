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
	adminv1.RegisterRoutes(mux, r.adminHandlers)
	apiv1.RegisterRoutes(mux, r.apiHandlers)
	return mux
}
