package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/example/ms-rbac-service/internal/domain"
	"github.com/example/ms-rbac-service/internal/domain/repository"
	"github.com/example/ms-rbac-service/internal/transport/http/common"
	"github.com/example/ms-rbac-service/internal/usecase"
)

// APIHandlers groups public API handlers.
type APIHandlers struct {
	PrincipalRole       *PrincipalRoleHandler
	PrincipalPermission *PrincipalPermissionHandler
}

type assignRoleRequest struct {
	Value struct {
		UserID string `json:"user_id"`
		Role   string `json:"role"`
	} `json:"value"`
}

// PrincipalRoleHandler handles principal role endpoints.
type PrincipalRoleHandler struct {
	Usecase *usecase.PrincipalRoleUsecase
}

func (h *PrincipalRoleHandler) Update(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		http.NotFound(w, r)
		return
	}
	if h.Usecase == nil {
		common.WriteError(w, http.StatusInternalServerError, "rbac principal role use case is unavailable")
		return
	}
	var payload assignRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		common.WriteError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	userID := strings.TrimSpace(payload.Value.UserID)
	role := strings.TrimSpace(payload.Value.Role)
	if userID == "" || role == "" {
		common.WriteError(w, http.StatusBadRequest, "user_id and role are required")
		return
	}
	if err := h.Usecase.Update(r.Context(), userID, repository.PrincipalRoleUpdate{RoleKey: role}); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			common.WriteError(w, http.StatusNotFound, "role not found")
			return
		}
		common.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *PrincipalRoleHandler) Get(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	if h.Usecase == nil {
		common.WriteError(w, http.StatusInternalServerError, "rbac principal role use case is unavailable")
		return
	}
	userID := strings.TrimSpace(r.URL.Query().Get("user_id"))
	if userID == "" {
		common.WriteError(w, http.StatusBadRequest, "user_id is required")
		return
	}
	role, err := h.Usecase.Get(r.Context(), userID)
	if err != nil {
		common.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]string{"role": role})
}

func (h *PrincipalRoleHandler) GetByRole(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	if h.Usecase == nil {
		common.WriteError(w, http.StatusInternalServerError, "rbac principal role use case is unavailable")
		return
	}
	userID := strings.TrimSpace(r.URL.Query().Get("user_id"))
	role := strings.TrimSpace(r.URL.Query().Get("role"))
	if userID == "" || role == "" {
		common.WriteError(w, http.StatusBadRequest, "user_id and role are required")
		return
	}
	allowed, err := h.Usecase.GetByRole(r.Context(), userID, role)
	if err != nil {
		common.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]bool{"allowed": allowed})
}

// PrincipalPermissionHandler handles permission lookup endpoints.
type PrincipalPermissionHandler struct {
	Usecase *usecase.PrincipalPermissionUsecase
}

func (h *PrincipalPermissionHandler) List(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	if h.Usecase == nil {
		common.WriteError(w, http.StatusInternalServerError, "rbac principal permission use case is unavailable")
		return
	}
	userID := strings.TrimSpace(r.URL.Query().Get("user_id"))
	if userID == "" {
		common.WriteError(w, http.StatusBadRequest, "user_id is required")
		return
	}
	perms, err := h.Usecase.List(r.Context(), userID)
	if err != nil {
		common.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string][]string{"permissions": perms})
}

func (h *PrincipalPermissionHandler) GetByPermission(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	if h.Usecase == nil {
		common.WriteError(w, http.StatusInternalServerError, "rbac principal permission use case is unavailable")
		return
	}
	userID := strings.TrimSpace(r.URL.Query().Get("user_id"))
	permission := strings.TrimSpace(r.URL.Query().Get("permission"))
	if userID == "" || permission == "" {
		common.WriteError(w, http.StatusBadRequest, "user_id and permission are required")
		return
	}
	allowed, err := h.Usecase.GetByPermission(r.Context(), userID, permission)
	if err != nil {
		common.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]bool{"allowed": allowed})
}
