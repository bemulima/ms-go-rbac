package http

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/example/ms-rbac-service/internal/domain/model"
	"github.com/example/ms-rbac-service/internal/domain/repository"
	"github.com/example/ms-rbac-service/internal/infrastructure/client"
	adminv1 "github.com/example/ms-rbac-service/internal/transport/http/admin/v1"
	adminhandlers "github.com/example/ms-rbac-service/internal/transport/http/admin/v1/handlers"
	apiv1 "github.com/example/ms-rbac-service/internal/transport/http/api/v1"
	apihandlers "github.com/example/ms-rbac-service/internal/transport/http/api/v1/handlers"
	"github.com/example/ms-rbac-service/internal/usecase"
)

// Spies sit below real usecases: denial must prevent reads (including replay)
// and writes, not merely return an expected status from a missing dependency.
type serviceAdmissionSpy struct{ calls *int }

func (s serviceAdmissionSpy) Create(context.Context, *model.Service) error { *s.calls++; return nil }
func (s serviceAdmissionSpy) Update(context.Context, string, string) error { *s.calls++; return nil }
func (s serviceAdmissionSpy) Get(context.Context, string) (*model.Service, error) {
	*s.calls++
	return &model.Service{}, nil
}
func (s serviceAdmissionSpy) List(context.Context, int, int) ([]model.Service, int64, error) {
	*s.calls++
	return []model.Service{}, 0, nil
}

type roleAdmissionSpy struct{ calls *int }

func (s roleAdmissionSpy) Create(context.Context, *model.Role) error    { *s.calls++; return nil }
func (s roleAdmissionSpy) Update(context.Context, string, string) error { *s.calls++; return nil }
func (s roleAdmissionSpy) Get(context.Context, string) (*model.Role, error) {
	*s.calls++
	return &model.Role{}, nil
}
func (s roleAdmissionSpy) List(context.Context, int, int) ([]model.Role, int64, error) {
	*s.calls++
	return []model.Role{}, 0, nil
}

type permissionAdmissionSpy struct{ calls *int }

func (s permissionAdmissionSpy) Create(context.Context, *model.Permission) error {
	*s.calls++
	return nil
}
func (s permissionAdmissionSpy) Update(context.Context, string, map[string]interface{}) error {
	*s.calls++
	return nil
}
func (s permissionAdmissionSpy) Get(context.Context, string) (*model.Permission, error) {
	*s.calls++
	return &model.Permission{}, nil
}
func (s permissionAdmissionSpy) List(context.Context, int, int) ([]model.Permission, int64, error) {
	*s.calls++
	return []model.Permission{}, 0, nil
}

type rolePermissionAdmissionSpy struct{ calls *int }

func (s rolePermissionAdmissionSpy) Create(context.Context, repository.RolePermissionCreate) error {
	*s.calls++
	return nil
}
func (s rolePermissionAdmissionSpy) ListByRoleKey(context.Context, string) ([]model.Permission, error) {
	*s.calls++
	return []model.Permission{}, nil
}

type principalAdmissionSpy struct{ calls *int }

func (s principalAdmissionSpy) Update(context.Context, string, repository.PrincipalRoleUpdate) error {
	*s.calls++
	return nil
}
func (s principalAdmissionSpy) Get(context.Context, string) (string, error) {
	*s.calls++
	return "admin", nil // Matching requested role would trigger an unauthorized replay.
}

type admissionRoute struct {
	method, path string
	raw          http.HandlerFunc
}

func admissionHandlers(calls *int, admission *usecase.MutationAdmission) (*adminhandlers.AdminHandlers, *apihandlers.APIHandlers, []admissionRoute) {
	principal := usecase.NewPrincipalRoleUsecase(principalAdmissionSpy{calls})
	rolePermissions := rolePermissionAdmissionSpy{calls}
	admin := &adminhandlers.AdminHandlers{
		Service:        &adminhandlers.ServiceHandler{Admission: admission, Usecase: usecase.NewServiceUsecase(serviceAdmissionSpy{calls})},
		Role:           &adminhandlers.RoleHandler{Admission: admission, Usecase: usecase.NewRoleUsecase(roleAdmissionSpy{calls})},
		Permission:     &adminhandlers.PermissionHandler{Admission: admission, Usecase: usecase.NewPermissionUsecase(permissionAdmissionSpy{calls})},
		RolePermission: &adminhandlers.RolePermissionHandler{Admission: admission, Usecase: usecase.NewRolePermissionUsecase(rolePermissions)},
	}
	api := &apihandlers.APIHandlers{
		PrincipalRole:       &apihandlers.PrincipalRoleHandler{Admission: admission, Usecase: principal},
		PrincipalPermission: &apihandlers.PrincipalPermissionHandler{Usecase: usecase.NewPrincipalPermissionUsecase(principalAdmissionSpy{calls}, rolePermissions)},
	}
	return admin, api, []admissionRoute{
		{http.MethodPatch, "/api/v1/principal-role/update", api.PrincipalRole.Update},
		{"SET", "/admin/v1/service", admin.Service.Create},
		{"SET", "/admin/v1/role", admin.Role.Create},
		{"SET", "/admin/v1/permission", admin.Permission.Create},
		{http.MethodPut, "/admin/v1/service/00000000-0000-4000-8000-000000000901", admin.Service.Update},
		{http.MethodPut, "/admin/v1/role/00000000-0000-4000-8000-000000000901", admin.Role.Update},
		{http.MethodPut, "/admin/v1/permission/00000000-0000-4000-8000-000000000901", admin.Permission.Update},
		{http.MethodPost, "/admin/v1/role-permission", admin.RolePermission.Create},
	}
}

type admissionBodySpy struct{ reads int }

func (b *admissionBodySpy) Read([]byte) (int, error) { b.reads++; return 0, io.EOF }
func (b *admissionBodySpy) Close() error             { return nil }

func TestEveryMutationRejectsBeforeBodyRepositoryAndReplay(t *testing.T) {
	for _, mode := range []string{"root-router", "child-mux", "raw-handler"} {
		for _, tc := range []struct {
			name                        string
			headers                     []string
			authorityStatus, wantStatus int
			claims                      map[string]any
			wantAuthorityCalls          int
		}{
			{"anonymous", nil, 200, 401, nil, 0},
			{"wrong-scheme", []string{"Basic synthetic"}, 200, 401, nil, 0},
			{"empty-bearer", []string{"Bearer "}, 200, 401, nil, 0},
			{"multiple-bearers", []string{"Bearer one", "Bearer two"}, 200, 401, nil, 0},
			{"combined-bearers", []string{"Bearer one, Bearer two"}, 200, 401, nil, 0},
			{"malformed-bearer", []string{"Bearer invalid!"}, 200, 401, nil, 0},
			{"forged-token", []string{"Bearer synthetic"}, 401, 401, nil, 1},
			{"student-identity", []string{"Bearer synthetic"}, 200, 403, map[string]any{"role": "student"}, 1},
			{"admin-identity", []string{"bEaReR synthetic"}, 200, 403, map[string]any{"role": "admin"}, 1},
			{"refresh", []string{"Bearer synthetic"}, 200, 401, map[string]any{"typ": "refresh"}, 1},
			{"non-access-purpose", []string{"Bearer synthetic"}, 200, 401, map[string]any{"purpose": "reset"}, 1},
			{"authority-failure", []string{"Bearer synthetic"}, 503, 503, nil, 1},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				var authorityCalls atomic.Int32
				authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					authorityCalls.Add(1)
					if r.Method != http.MethodPost || r.URL.Path != "/api/v1/auth/verify" {
						t.Error("incorrect authority wire contract")
					}
					claims := map[string]any{"iss": "auth-service", "aud": "frontend", "exp": time.Now().Add(time.Hour).Unix()}
					for key, value := range tc.claims {
						claims[key] = value
					}
					w.WriteHeader(tc.authorityStatus)
					_ = json.NewEncoder(w).Encode(map[string]any{"user_id": "00000000-0000-4000-8000-000000000901", "claims": claims})
				}))
				defer authority.Close()
				verifier, err := client.NewAuthVerifier(authority.URL + "/api/v1/auth/verify")
				if err != nil {
					t.Fatal(err)
				}
				repositoryCalls := 0
				admin, api, routes := admissionHandlers(&repositoryCalls, usecase.NewMutationAdmission(verifier))
				root := NewRouter(admin, api).Handler()
				adminMux, apiMux := http.NewServeMux(), http.NewServeMux()
				adminv1.RegisterRoutes(adminMux, admin)
				apiv1.RegisterRoutes(apiMux, api)
				for _, route := range routes {
					t.Run(route.method+route.path, func(t *testing.T) {
						path, handler := route.path, root
						if mode == "child-mux" {
							if strings.HasPrefix(path, "/admin/v1") {
								path = strings.TrimPrefix(path, "/admin/v1")
								handler = adminMux
							} else {
								path = strings.TrimPrefix(path, "/api/v1")
								handler = apiMux
							}
						} else if mode == "raw-handler" {
							handler = route.raw
						}
						req := httptest.NewRequest(route.method, path, nil)
						body := &admissionBodySpy{}
						req.Body = body
						for _, header := range tc.headers {
							req.Header.Add("Authorization", header)
						}
						req.Header.Set("X-User-Id", "00000000-0000-4000-8000-000000000901")
						req.Header.Set("X-User-Role", "admin")
						req.Header.Set("X-RBAC-Scope", "global")
						before := authorityCalls.Load()
						rr := httptest.NewRecorder()
						handler.ServeHTTP(rr, req)
						if rr.Code != tc.wantStatus {
							t.Fatalf("want %d, got %d", tc.wantStatus, rr.Code)
						}
						if authorityCalls.Load()-before != int32(tc.wantAuthorityCalls) {
							t.Fatal("authority call ordering violated")
						}
						if repositoryCalls != 0 || body.reads != 0 {
							t.Fatalf("denial reached repository=%d/body=%d", repositoryCalls, body.reads)
						}
						if strings.Contains(rr.Body.String(), "synthetic") {
							t.Fatal("response leaked credential")
						}
					})
				}
			})
		}
	}
}

func TestMissingAuthorityAndAlternatePathsRemainClosed(t *testing.T) {
	calls := 0
	admin, api, routes := admissionHandlers(&calls, nil)
	handler := NewRouter(admin, api).Handler()
	for _, route := range routes {
		for _, authorization := range []string{"", "Bearer synthetic"} {
			req := httptest.NewRequest(route.method, route.path, nil)
			if authorization != "" {
				req.Header.Set("Authorization", authorization)
			}
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			want := 401
			if authorization != "" {
				want = 503
			}
			if rr.Code != want {
				t.Fatalf("default admission got %d, want %d", rr.Code, want)
			}
		}
	}
	for _, path := range []string{"/admin/v1/role/nested/id", "/admin/v1/role/%61dmin", "/admin/v1/role/", "/admin/v1/role//id", "/admin/v1/role/../role/id"} {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPut, path, nil))
		if rr.Code == 301 {
			follow := httptest.NewRecorder()
			handler.ServeHTTP(follow, httptest.NewRequest(http.MethodPut, rr.Header().Get("Location"), nil))
			rr = follow
		}
		if rr.Code != 401 {
			t.Fatalf("alternate path admission got %d", rr.Code)
		}
	}
	if calls != 0 {
		t.Fatal("missing authority or alternate path reached repository")
	}
}

func TestPublicReadsAndExistingWrongMethodsRemainCompatible(t *testing.T) {
	calls := 0
	admin, api, _ := admissionHandlers(&calls, nil)
	handler := NewRouter(admin, api).Handler()
	for _, path := range []string{
		"/admin/v1/service/id", "/admin/v1/service-list", "/admin/v1/role/id", "/admin/v1/role-list", "/admin/v1/permission/id", "/admin/v1/permission-list",
		"/api/v1/principal-role/get?user_id=principal", "/api/v1/principal-role/get-by-role?user_id=principal&role=admin",
		"/api/v1/principal-permission/list?user_id=principal", "/api/v1/principal-permission/get-by-permission?user_id=principal&permission=read",
	} {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != 200 {
			t.Fatalf("public read %s got %d", path, rr.Code)
		}
	}
	if calls == 0 {
		t.Fatal("public read never reached usecase/repository")
	}
	before := calls
	for _, route := range []struct{ method, path string }{{"POST", "/admin/v1/role"}, {"DELETE", "/admin/v1/role/id"}, {"GET", "/api/v1/principal-role/update"}, {"PATCH", "/admin/v1/role-permission"}} {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, httptest.NewRequest(route.method, route.path, nil))
		if rr.Code != 404 {
			t.Fatalf("wrong method %s got %d", fmt.Sprint(route), rr.Code)
		}
	}
	if calls != before {
		t.Fatal("unsupported mutation reached repository")
	}
}
