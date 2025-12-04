package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	repo "github.com/example/ms-rbac-service/internal/adapters/postgres"
	"github.com/example/ms-rbac-service/internal/usecase"
)

type APIHandlers struct {
	Permission *usecase.PermissionUsecase
	Principal  *usecase.PrincipalUsecase
}

type assignRoleRequest struct {
	Value struct {
		UserID string `json:"user_id"`
		Role   string `json:"role"`
	} `json:"value"`
}

func (h *APIHandlers) HandleAssignRole(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if h.Principal == nil {
		writeError(w, http.StatusInternalServerError, "rbac principal use case is unavailable")
		return
	}
	var payload assignRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	userID := strings.TrimSpace(payload.Value.UserID)
	role := strings.TrimSpace(payload.Value.Role)
	if userID == "" || role == "" {
		writeError(w, http.StatusBadRequest, "user_id and role are required")
		return
	}
	if err := h.Principal.AssignRole(r.Context(), userID, role); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			writeError(w, http.StatusNotFound, "role not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *APIHandlers) HandleGetRoleByUserID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	if h.Principal == nil {
		writeError(w, http.StatusInternalServerError, "rbac principal use case is unavailable")
		return
	}
	userID := strings.TrimSpace(r.URL.Query().Get("user_id"))
	if userID == "" {
		writeError(w, http.StatusBadRequest, "user_id is required")
		return
	}
	role, err := h.Principal.GetRole(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"role": role})
}

func (h *APIHandlers) HandleGetPermissionsByUserID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	if h.Principal == nil {
		writeError(w, http.StatusInternalServerError, "rbac principal use case is unavailable")
		return
	}
	userID := strings.TrimSpace(r.URL.Query().Get("user_id"))
	if userID == "" {
		writeError(w, http.StatusBadRequest, "user_id is required")
		return
	}
	perms, err := h.Principal.GetPermissions(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string][]string{"permissions": perms})
}

func (h *APIHandlers) HandleCheckRoleByUserID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	if h.Principal == nil {
		writeError(w, http.StatusInternalServerError, "rbac principal use case is unavailable")
		return
	}
	userID := strings.TrimSpace(r.URL.Query().Get("user_id"))
	role := strings.TrimSpace(r.URL.Query().Get("role"))
	if userID == "" || role == "" {
		writeError(w, http.StatusBadRequest, "user_id and role are required")
		return
	}
	allowed, err := h.Principal.CheckRole(r.Context(), userID, role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"allowed": allowed})
}

func (h *APIHandlers) HandleCheckPermissionByUserID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	if h.Principal == nil {
		writeError(w, http.StatusInternalServerError, "rbac principal use case is unavailable")
		return
	}
	userID := strings.TrimSpace(r.URL.Query().Get("user_id"))
	permission := strings.TrimSpace(r.URL.Query().Get("permission"))
	if userID == "" || permission == "" {
		writeError(w, http.StatusBadRequest, "user_id and permission are required")
		return
	}
	allowed, err := h.Principal.CheckPermission(r.Context(), userID, permission)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"allowed": allowed})
}
