package pagination

import (
	"math"
)

const (
	DefaultPage     = 1
	DefaultPageSize = 25
	MaxPageSize     = 100
)

// Params describes pagination query parameters.
type Params struct {
	Page     int
	PageSize int
}

// Result describes paginated response metadata.
type Result struct {
	Page     int         `json:"page"`
	PageSize int         `json:"pageSize"`
	Total    int64       `json:"total"`
	Items    interface{} `json:"items"`
}

// NewParams normalises page and page size ensuring sane defaults.
func NewParams(page, pageSize int) Params {
	if page <= 0 {
		page = DefaultPage
	}
	if pageSize <= 0 {
		pageSize = DefaultPageSize
	}
	if pageSize > MaxPageSize {
		pageSize = MaxPageSize
	}
	return Params{
		Page:     page,
		PageSize: pageSize,
	}
}

// Offset returns the calculated offset for the provided pagination parameters.
func (p Params) Offset() int {
	if p.Page <= 1 {
		return 0
	}
	return int(math.Max(0, float64((p.Page-1)*p.PageSize)))
}
