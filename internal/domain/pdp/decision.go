package pdp

import "github.com/example/ms-rbac-service/internal/domain/model"

// CheckRequest represents a PDP input payload.
type CheckRequest struct {
	PrincipalID   string
	PrincipalKind model.PrincipalKind
	TenantID      *string
	ServiceID     *string
	Action        string
	ResourceKind  string
	ResourceID    *string
	CorrelationID string
}

// CheckResult represents the decision returned by the PDP engine.
type CheckResult struct {
	Allow         bool     `json:"allow"`
	Decision      string   `json:"decision"`
	RoleKeys      []string `json:"role_keys,omitempty"`
	CorrelationID string   `json:"correlation_id,omitempty"`
}

// ExplainResult enriches the response with the matched artefacts.
type ExplainResult struct {
	Allow    bool        `json:"allow"`
	Decision string      `json:"decision"`
	Matched  interface{} `json:"matched,omitempty"`
}

// Repository is the contract required by the PDP engine for loading state.
type Repository interface {
	IsSuperAdmin(principalID string, kind model.PrincipalKind) (bool, error)
	FindMostSpecificOverride(req CheckRequest) (*OverrideMatch, error)
	ResolveRoles(req CheckRequest) ([]RoleWithScope, error)
	ListPermissionsForRoles(roleIDs []string) ([]RolePermissionItem, error)
}

type OverrideMatch struct {
	Effect       model.OverrideEffect
	PermissionID string
	Scope        OverrideScope
}

type OverrideScope struct {
	TenantID     *string
	ServiceID    *string
	ResourceKind *string
	ResourceID   *string
}

type RoleWithScope struct {
	RoleID     string
	RoleKey    string
	Scope      OverrideScope
	ServiceIDs []string
}

type RolePermissionItem struct {
	RoleID       string
	RoleKey      string
	PermissionID string
	Action       string
	ResourceKind string
	ResourceID   *string
}
