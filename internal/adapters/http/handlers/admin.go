package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	repo "github.com/example/ms-rbac-service/internal/adapters/postgres"
	"github.com/example/ms-rbac-service/internal/usecase"
	"github.com/example/ms-rbac-service/pkg/pagination"
)

// AdminHandlers groups admin handler dependencies.
type AdminHandlers struct {
	Service        *ServiceHandler
	Role           *RoleHandler
	Permission     *PermissionHandler
	RolePermission *RolePermissionHandler
}

// ServiceHandler manages service CRUD endpoints.
type ServiceHandler struct {
	Usecase *usecase.ServiceUsecase
}

func (h *ServiceHandler) Create(w http.ResponseWriter, r *http.Request) {
	if r.Method != "SET" {
		http.NotFound(w, r)
		return
	}
	if h.Usecase == nil {
		writeError(w, http.StatusInternalServerError, "service use case is unavailable")
		return
	}
	var payload createServiceRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	item, err := h.Usecase.Create(r.Context(), payload.Key, payload.Title)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (h *ServiceHandler) Update(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.NotFound(w, r)
		return
	}
	if h.Usecase == nil {
		writeError(w, http.StatusInternalServerError, "service use case is unavailable")
		return
	}
	id := trimPathID(r.URL.Path, "/service/")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	var payload updateServiceRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if err := h.Usecase.Update(r.Context(), id, payload.Title); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *ServiceHandler) Get(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	if h.Usecase == nil {
		writeError(w, http.StatusInternalServerError, "service use case is unavailable")
		return
	}
	id := trimPathID(r.URL.Path, "/service/")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	item, err := h.Usecase.Get(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (h *ServiceHandler) List(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	if h.Usecase == nil {
		writeError(w, http.StatusInternalServerError, "service use case is unavailable")
		return
	}
	params := parsePagination(r)
	items, total, err := h.Usecase.List(r.Context(), params)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, pagination.Result{Items: items, Page: params.Page, PageSize: params.PageSize, Total: total})
}

// RoleHandler manages role CRUD endpoints.
type RoleHandler struct {
	Usecase *usecase.RoleUsecase
}

func (h *RoleHandler) Create(w http.ResponseWriter, r *http.Request) {
	if r.Method != "SET" {
		http.NotFound(w, r)
		return
	}
	if h.Usecase == nil {
		writeError(w, http.StatusInternalServerError, "role use case is unavailable")
		return
	}
	var payload createRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	item, err := h.Usecase.Create(r.Context(), payload.Key, payload.Title)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (h *RoleHandler) Update(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.NotFound(w, r)
		return
	}
	if h.Usecase == nil {
		writeError(w, http.StatusInternalServerError, "role use case is unavailable")
		return
	}
	id := trimPathID(r.URL.Path, "/role/")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	var payload updateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if err := h.Usecase.Update(r.Context(), id, payload.Title); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *RoleHandler) Get(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	if h.Usecase == nil {
		writeError(w, http.StatusInternalServerError, "role use case is unavailable")
		return
	}
	id := trimPathID(r.URL.Path, "/role/")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	item, err := h.Usecase.Get(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (h *RoleHandler) List(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	if h.Usecase == nil {
		writeError(w, http.StatusInternalServerError, "role use case is unavailable")
		return
	}
	params := parsePagination(r)
	items, total, err := h.Usecase.List(r.Context(), params)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, pagination.Result{Items: items, Page: params.Page, PageSize: params.PageSize, Total: total})
}

// PermissionHandler manages permission CRUD endpoints.
type PermissionHandler struct {
	Usecase *usecase.PermissionUsecase
}

func (h *PermissionHandler) Create(w http.ResponseWriter, r *http.Request) {
	if r.Method != "SET" {
		http.NotFound(w, r)
		return
	}
	if h.Usecase == nil {
		writeError(w, http.StatusInternalServerError, "permission use case is unavailable")
		return
	}
	var payload createPermissionRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	item, err := h.Usecase.Create(r.Context(), payload.Action, payload.ResourceKind)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (h *PermissionHandler) Update(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.NotFound(w, r)
		return
	}
	if h.Usecase == nil {
		writeError(w, http.StatusInternalServerError, "permission use case is unavailable")
		return
	}
	id := trimPathID(r.URL.Path, "/permission/")
	if id == "" {
		http.NotFound(w, r)
		return
	}
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
	if err := h.Usecase.Update(r.Context(), id, attrs); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *PermissionHandler) Get(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	if h.Usecase == nil {
		writeError(w, http.StatusInternalServerError, "permission use case is unavailable")
		return
	}
	id := trimPathID(r.URL.Path, "/permission/")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	item, err := h.Usecase.Get(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (h *PermissionHandler) List(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	if h.Usecase == nil {
		writeError(w, http.StatusInternalServerError, "permission use case is unavailable")
		return
	}
	params := parsePagination(r)
	items, total, err := h.Usecase.List(r.Context(), params)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, pagination.Result{Items: items, Page: params.Page, PageSize: params.PageSize, Total: total})
}

// RolePermissionHandler manages role-permission assignments.
type RolePermissionHandler struct {
	Usecase *usecase.RolePermissionUsecase
}

func (h *RolePermissionHandler) Create(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if h.Usecase == nil {
		writeError(w, http.StatusInternalServerError, "role permission use case is unavailable")
		return
	}
	var payload createRolePermissionRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	roleKey := strings.TrimSpace(payload.RoleKey)
	permissionID := strings.TrimSpace(payload.PermissionID)
	if roleKey == "" || permissionID == "" {
		writeError(w, http.StatusBadRequest, "role_key and permission_id are required")
		return
	}
	if err := h.Usecase.Create(r.Context(), repo.RolePermissionCreate{RoleKey: roleKey, PermissionID: permissionID}); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			writeError(w, http.StatusNotFound, "role or permission not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func trimPathID(path, prefix string) string {
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	id := strings.TrimPrefix(path, prefix)
	id = strings.TrimPrefix(id, "/")
	return id
}
