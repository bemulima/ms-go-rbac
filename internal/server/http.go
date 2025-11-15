package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/example/ms-rbac-service/internal/usecase"
	"github.com/example/ms-rbac-service/pkg/pagination"
)

type Server struct {
	mux          *http.ServeMux
	serviceUC    *usecase.ServiceUsecase
	roleUC       *usecase.RoleUsecase
	permissionUC *usecase.PermissionUsecase
}

func New(serviceUC *usecase.ServiceUsecase, roleUC *usecase.RoleUsecase, permissionUC *usecase.PermissionUsecase) *Server {
	s := &Server{
		mux:          http.NewServeMux(),
		serviceUC:    serviceUC,
		roleUC:       roleUC,
		permissionUC: permissionUC,
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("/admin/service", s.handleService)
	s.mux.HandleFunc("/admin/service/", s.handleService)
	s.mux.HandleFunc("/admin/service-list", s.handleServiceList)
	s.mux.HandleFunc("/admin/role", s.handleRole)
	s.mux.HandleFunc("/admin/role/", s.handleRole)
	s.mux.HandleFunc("/admin/role-list", s.handleRoleList)
	s.mux.HandleFunc("/admin/permission", s.handlePermission)
	s.mux.HandleFunc("/admin/permission/", s.handlePermission)
	s.mux.HandleFunc("/admin/permission-list", s.handlePermissionList)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

type createServiceRequest struct {
	Key   string `json:"key"`
	Title string `json:"title"`
}

type updateServiceRequest struct {
	Title string `json:"title"`
}

func (s *Server) handleService(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/admin/service")
	switch {
	case r.Method == "SET" && (path == "" || path == "/"):
		var payload createServiceRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}
		item, err := s.serviceUC.Create(r.Context(), payload.Key, payload.Title)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, item)
	case r.Method == "PUT" && strings.HasPrefix(path, "/"):
		id := strings.TrimPrefix(path, "/")
		var payload updateServiceRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}
		if err := s.serviceUC.Update(r.Context(), id, payload.Title); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case r.Method == "GET" && strings.HasPrefix(path, "/"):
		id := strings.TrimPrefix(path, "/")
		item, err := s.serviceUC.Get(r.Context(), id)
		if err != nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, item)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleServiceList(w http.ResponseWriter, r *http.Request) {
	params := parsePagination(r)
	items, total, err := s.serviceUC.List(r.Context(), params)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, pagination.Result{Items: items, Page: params.Page, PageSize: params.PageSize, Total: total})
}

type createRoleRequest struct {
	Key   string `json:"key"`
	Title string `json:"title"`
}

type updateRoleRequest struct {
	Title string `json:"title"`
}

func (s *Server) handleRole(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/admin/role")
	switch {
	case r.Method == "SET" && (path == "" || path == "/"):
		var payload createRoleRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}
		item, err := s.roleUC.Create(r.Context(), payload.Key, payload.Title)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, item)
	case r.Method == "PUT" && strings.HasPrefix(path, "/"):
		id := strings.TrimPrefix(path, "/")
		var payload updateRoleRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}
		if err := s.roleUC.Update(r.Context(), id, payload.Title); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case r.Method == "GET" && strings.HasPrefix(path, "/"):
		id := strings.TrimPrefix(path, "/")
		item, err := s.roleUC.Get(r.Context(), id)
		if err != nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, item)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleRoleList(w http.ResponseWriter, r *http.Request) {
	params := parsePagination(r)
	items, total, err := s.roleUC.List(r.Context(), params)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, pagination.Result{Items: items, Page: params.Page, PageSize: params.PageSize, Total: total})
}

type createPermissionRequest struct {
	Action       string `json:"action"`
	ResourceKind string `json:"resource_kind"`
}

type updatePermissionRequest struct {
	Action       *string `json:"action"`
	ResourceKind *string `json:"resource_kind"`
}

func (s *Server) handlePermission(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/admin/permission")
	switch {
	case r.Method == "SET" && (path == "" || path == "/"):
		var payload createPermissionRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}
		item, err := s.permissionUC.Create(r.Context(), payload.Action, payload.ResourceKind)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, item)
	case r.Method == "PUT" && strings.HasPrefix(path, "/"):
		id := strings.TrimPrefix(path, "/")
		var payload updatePermissionRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}
		attrs := map[string]interface{}{}
		if payload.Action != nil {
			attrs["action"] = *payload.Action
		}
		if payload.ResourceKind != nil {
			attrs["resource_kind"] = *payload.ResourceKind
		}
		if len(attrs) == 0 {
			writeError(w, http.StatusBadRequest, "no updates supplied")
			return
		}
		if err := s.permissionUC.Update(r.Context(), id, attrs); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case r.Method == "GET" && strings.HasPrefix(path, "/"):
		id := strings.TrimPrefix(path, "/")
		item, err := s.permissionUC.Get(r.Context(), id)
		if err != nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, item)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handlePermissionList(w http.ResponseWriter, r *http.Request) {
	params := parsePagination(r)
	items, total, err := s.permissionUC.List(r.Context(), params)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, pagination.Result{Items: items, Page: params.Page, PageSize: params.PageSize, Total: total})
}

func parsePagination(r *http.Request) pagination.Params {
	q := r.URL.Query()
	page := parseInt(q.Get("page"))
	pageSize := parseInt(q.Get("pageSize"))
	return pagination.NewParams(page, pageSize)
}

func parseInt(v string) int {
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0
	}
	return n
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]interface{}{
		"error": map[string]interface{}{
			"code":    "RBAC_ERROR",
			"message": message,
		},
	})
}
