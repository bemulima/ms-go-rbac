package http

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	adminhandlers "github.com/example/ms-rbac-service/internal/transport/http/admin/v1/handlers"
	apihandlers "github.com/example/ms-rbac-service/internal/transport/http/api/v1/handlers"
)

func TestMutationsDenyAnonymousAndSpoofedActorsByDefault(t *testing.T) {
	router := NewRouter(&adminhandlers.AdminHandlers{
		Service: &adminhandlers.ServiceHandler{}, Role: &adminhandlers.RoleHandler{},
		Permission: &adminhandlers.PermissionHandler{}, RolePermission: &adminhandlers.RolePermissionHandler{},
	}, &apihandlers.APIHandlers{PrincipalRole: &apihandlers.PrincipalRoleHandler{}, PrincipalPermission: &apihandlers.PrincipalPermissionHandler{}})
	for _, route := range []struct{ method, path string }{
		{http.MethodPatch, "/api/v1/principal-role/update"}, {"SET", "/admin/v1/role"},
		{http.MethodPut, "/admin/v1/permission/id"}, {http.MethodPost, "/admin/v1/role-permission"},
	} {
		t.Run(route.method+route.path, func(t *testing.T) {
			req := httptest.NewRequest(route.method, route.path, strings.NewReader(`{"value":{"user_id":"victim","role":"admin"}}`))
			req.Header.Set("X-User-Id", "forged-admin")
			req.Header.Set("X-User-Role", "admin")
			rr := httptest.NewRecorder()
			router.Handler().ServeHTTP(rr, req)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("want 401 before usecase, got %d: %s", rr.Code, rr.Body.String())
			}
		})
	}
}
