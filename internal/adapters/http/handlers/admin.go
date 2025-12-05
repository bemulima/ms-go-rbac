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

type AdminHandlers struct {
	Service    *usecase.ServiceUsecase
	Role       *usecase.RoleUsecase
	Permission *usecase.PermissionUsecase
	Principal  *usecase.PrincipalUsecase
}

func (h *AdminHandlers) HandleService(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/service")
	switch {
	case r.Method == "SET" && (path == "" || path == "/"):
		var payload createServiceRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}
		item, err := h.Service.Create(r.Context(), payload.Key, payload.Title)
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
		if err := h.Service.Update(r.Context(), id, payload.Title); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case r.Method == "GET" && strings.HasPrefix(path, "/"):
		id := strings.TrimPrefix(path, "/")
		item, err := h.Service.Get(r.Context(), id)
		if err != nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, item)
	default:
		http.NotFound(w, r)
	}
}

func (h *AdminHandlers) HandleServiceList(w http.ResponseWriter, r *http.Request) {
	params := parsePagination(r)
	items, total, err := h.Service.List(r.Context(), params)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, pagination.Result{Items: items, Page: params.Page, PageSize: params.PageSize, Total: total})
}

func (h *AdminHandlers) HandleRole(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/role")
	switch {
	case r.Method == "SET" && (path == "" || path == "/"):
		var payload createRoleRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}
		item, err := h.Role.Create(r.Context(), payload.Key, payload.Title)
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
		if err := h.Role.Update(r.Context(), id, payload.Title); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case r.Method == "GET" && strings.HasPrefix(path, "/"):
		id := strings.TrimPrefix(path, "/")
		item, err := h.Role.Get(r.Context(), id)
		if err != nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, item)
	default:
		http.NotFound(w, r)
	}
}

func (h *AdminHandlers) HandleRoleList(w http.ResponseWriter, r *http.Request) {
	params := parsePagination(r)
	items, total, err := h.Role.List(r.Context(), params)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, pagination.Result{Items: items, Page: params.Page, PageSize: params.PageSize, Total: total})
}

func (h *AdminHandlers) HandlePermission(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/permission")
	switch {
	case r.Method == "SET" && (path == "" || path == "/"):
		var payload createPermissionRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}
		item, err := h.Permission.Create(r.Context(), payload.Action, payload.ResourceKind)
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
		if err := h.Permission.Update(r.Context(), id, attrs); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case r.Method == "GET" && strings.HasPrefix(path, "/"):
		id := strings.TrimPrefix(path, "/")
		item, err := h.Permission.Get(r.Context(), id)
		if err != nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, item)
	default:
		http.NotFound(w, r)
	}
}

func (h *AdminHandlers) HandlePermissionList(w http.ResponseWriter, r *http.Request) {
	params := parsePagination(r)
	items, total, err := h.Permission.List(r.Context(), params)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, pagination.Result{Items: items, Page: params.Page, PageSize: params.PageSize, Total: total})
}

func (h *AdminHandlers) HandleRolePermission(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
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
	if err := h.Permission.AssignToRole(r.Context(), roleKey, permissionID); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			writeError(w, http.StatusNotFound, "role or permission not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
