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
	adminHandlers  *adminhandlers.AdminHandlers
	apiHandlers    *apihandlers.APIHandlers
	ideStudentRole *private.IDEStudentRoleHandler
}

func NewRouter(adminHandlers *adminhandlers.AdminHandlers, apiHandlers *apihandlers.APIHandlers) *Router {
	return &Router{adminHandlers: adminHandlers, apiHandlers: apiHandlers}
}

// SetIDEStudentRoleRead configures the optional, dedicated IDE28 private read.
// Nil/default leaves the endpoint entirely absent.
func (r *Router) SetIDEStudentRoleRead(handler *private.IDEStudentRoleHandler) {
	r.ideStudentRole = handler
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
	private.RegisterIDEStudentRoleRoutes(privateMux, r.ideStudentRole)
	mux.Handle("/private/", http.StripPrefix("/private", privateMux))

	// No network caller currently has a verified role-management authority.
	// Keep read contracts and signed NATS signup; never trust actor headers.
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			mux.ServeHTTP(w, req)
		default:
			http.Error(w, "HTTP mutations disabled; use operator bootstrap", http.StatusForbidden)
		}
	})
}
