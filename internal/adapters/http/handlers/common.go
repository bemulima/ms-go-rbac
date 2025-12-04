package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/example/ms-rbac-service/pkg/pagination"
)

type createServiceRequest struct {
	Key   string `json:"key"`
	Title string `json:"title"`
}

type updateServiceRequest struct {
	Title string `json:"title"`
}

type createRoleRequest struct {
	Key   string `json:"key"`
	Title string `json:"title"`
}

type updateRoleRequest struct {
	Title string `json:"title"`
}

type createPermissionRequest struct {
	Action       string `json:"action"`
	ResourceKind string `json:"resource_kind"`
}

type updatePermissionRequest struct {
	Action       *string `json:"action"`
	ResourceKind *string `json:"resource_kind"`
}

type createRolePermissionRequest struct {
	RoleKey      string `json:"role_key"`
	PermissionID string `json:"permission_id"`
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
