package common

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/example/ms-rbac-service/pkg/pagination"
)

func ParsePagination(r *http.Request) pagination.Params {
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

func WriteJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func WriteError(w http.ResponseWriter, status int, message string) {
	WriteJSON(w, status, map[string]interface{}{
		"error": map[string]interface{}{
			"code":    "RBAC_ERROR",
			"message": message,
		},
	})
}
