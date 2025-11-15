package repo

import "time"

type BaseModel struct {
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Service struct {
	ID    string
	Key   string
	Title string
	BaseModel
}

type Role struct {
	ID    string
	Key   string
	Title string
	BaseModel
}

type RoleHierarchy struct {
	RoleID       string
	ParentRoleID string
	BaseModel
}

type Permission struct {
	ID           string
	Action       string
	ResourceKind string
	BaseModel
}

type RolePermission struct {
	RoleID       string
	PermissionID string
	ResourceID   *string
	BaseModel
}

type ServiceRole struct {
	RoleID    string
	ServiceID string
	BaseModel
}

type ServicePermission struct {
	PermissionID string
	ServiceID    string
	BaseModel
}

type PrincipalKind string

type PrincipalRole struct {
	PrincipalID   string
	PrincipalKind PrincipalKind
	RoleID        string
	TenantID      *string
	ServiceID     *string
	ResourceKind  *string
	ResourceID    *string
	BaseModel
}

type OverrideEffect string

type PrincipalOverride struct {
	PrincipalID   string
	PrincipalKind PrincipalKind
	PermissionID  string
	Effect        OverrideEffect
	TenantID      *string
	ServiceID     *string
	ResourceKind  *string
	ResourceID    *string
	BaseModel
}

type SuperadminPrincipal struct {
	PrincipalID   string
	PrincipalKind PrincipalKind
	BaseModel
}
