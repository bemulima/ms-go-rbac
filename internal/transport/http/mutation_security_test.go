package http

import (
	admin "github.com/example/ms-rbac-service/internal/transport/http/admin/v1/handlers"
	api "github.com/example/ms-rbac-service/internal/transport/http/api/v1/handlers"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNetworkMutationAlwaysDenied(t *testing.T) {
	handler := NewRouter(&admin.AdminHandlers{}, &api.APIHandlers{}).Handler()
	for _, actor := range []string{"anonymous", "STUDENT", "MODERATOR", "ADMIN"} {
		for _, route := range []struct{ method, path string }{{"PATCH", "/api/v1/principal-role/update"}, {"POST", "/admin/v1/role-permission"}, {"PUT", "/admin/v1/role/id"}, {"PUT", "/admin/v1/permission/id"}, {"SET", "/admin/v1/role"}, {"DELETE", "/admin/v1/role/id"}} {
			t.Run(actor+route.method+route.path, func(t *testing.T) {
				req := httptest.NewRequest(route.method, route.path, strings.NewReader(`{"value":{"user_id":"self","role":"admin"}}`))
				if actor != "anonymous" {
					req.Header.Set("Authorization", "Bearer untrusted")
					req.Header.Set("X-User-Id", "self")
					req.Header.Set("X-User-Role", actor)
					req.Header.Set("X-Internal-Token", "forged")
				}
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code != http.StatusForbidden {
					t.Fatalf("got %d", rec.Code)
				}
			})
		}
	}
}
