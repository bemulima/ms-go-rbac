package model

// Service represents an external system registered within RBAC.
type Service struct {
	ID    string
	Key   string
	Title string
}

// Role represents a named role with a key.
type Role struct {
	ID    string
	Key   string
	Title string
}

// Permission represents an action that can be applied to a resource kind.
type Permission struct {
	ID           string
	Action       string
	ResourceKind string
}

type RoleHierarchy struct {
	RoleID       string
	ParentRoleID string
}

type RolePermission struct {
	RoleID       string
	PermissionID string
	ResourceID   *string
}

type ServiceRole struct {
	RoleID    string
	ServiceID string
}

type ServicePermission struct {
	PermissionID string
	ServiceID    string
}

type PrincipalKind string

const (
	PrincipalKindUser           PrincipalKind = "user"
	PrincipalKindServiceAccount PrincipalKind = "service_account"
	PrincipalKindGroup          PrincipalKind = "group"
)

type PrincipalRole struct {
	PrincipalID   string
	PrincipalKind PrincipalKind
	RoleID        string
	TenantID      *string
	ServiceID     *string
	ResourceKind  *string
	ResourceID    *string
}

type OverrideEffect string

const (
	OverrideEffectAllow OverrideEffect = "allow"
	OverrideEffectDeny  OverrideEffect = "deny"
)

type PrincipalOverride struct {
	PrincipalID   string
	PrincipalKind PrincipalKind
	PermissionID  string
	Effect        OverrideEffect
	TenantID      *string
	ServiceID     *string
	ResourceKind  *string
	ResourceID    *string
}

type SuperadminPrincipal struct {
	PrincipalID   string
	PrincipalKind PrincipalKind
}
