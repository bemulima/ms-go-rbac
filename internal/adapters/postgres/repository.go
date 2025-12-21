package repo

import (
	"context"
	"errors"

	"github.com/example/ms-rbac-service/internal/domain/model"
	domainpdp "github.com/example/ms-rbac-service/internal/domain/pdp"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	defaultTenantID   = "00000000-0000-0000-0000-000000000000"
	defaultServiceID  = "00000000-0000-0000-0000-000000000100"
	defaultResourceID = "00000000-0000-0000-0000-000000000000"
	defaultScopeKind  = "global"
	defaultRoleKind   = model.PrincipalKindUser
)

// Repository provides Postgres-backed storage for RBAC entities.
type Repository struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

func (r *Repository) Close() {
	if r.pool != nil {
		r.pool.Close()
	}
}

func (r *Repository) CreateService(ctx context.Context, service *Service) error {
	query := `INSERT INTO service (key, title) VALUES ($1, $2) RETURNING id::text`
	return r.pool.QueryRow(ctx, query, service.Key, service.Title).Scan(&service.ID)
}

func (r *Repository) UpdateService(ctx context.Context, id string, title string) error {
	cmd, err := r.pool.Exec(ctx, `UPDATE service SET title=$2 WHERE id::text=$1`, id, title)
	if err != nil {
		return err
	}
	if cmd.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *Repository) GetService(ctx context.Context, id string) (*Service, error) {
	var svc Service
	row := r.pool.QueryRow(ctx, `SELECT id::text, key, title FROM service WHERE id::text=$1`, id)
	if err := row.Scan(&svc.ID, &svc.Key, &svc.Title); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &svc, nil
}

func (r *Repository) ListServices(ctx context.Context, offset, limit int) ([]Service, int64, error) {
	var total int64
	if err := r.pool.QueryRow(ctx, `SELECT count(*) FROM service`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.pool.Query(ctx, `SELECT id::text, key, title FROM service ORDER BY key LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := make([]Service, 0)
	for rows.Next() {
		var svc Service
		if err := rows.Scan(&svc.ID, &svc.Key, &svc.Title); err != nil {
			return nil, 0, err
		}
		items = append(items, svc)
	}
	return items, total, rows.Err()
}

func (r *Repository) CreateRole(ctx context.Context, role *Role) error {
	query := `INSERT INTO role (key, title) VALUES ($1, $2) RETURNING id::text`
	return r.pool.QueryRow(ctx, query, role.Key, role.Title).Scan(&role.ID)
}

func (r *Repository) UpdateRole(ctx context.Context, id string, title string) error {
	cmd, err := r.pool.Exec(ctx, `UPDATE role SET title=$2 WHERE id::text=$1`, id, title)
	if err != nil {
		return err
	}
	if cmd.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *Repository) GetRole(ctx context.Context, id string) (*Role, error) {
	var role Role
	row := r.pool.QueryRow(ctx, `SELECT id::text, key, title FROM role WHERE id::text=$1`, id)
	if err := row.Scan(&role.ID, &role.Key, &role.Title); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &role, nil
}

func (r *Repository) ListRoles(ctx context.Context, offset, limit int) ([]Role, int64, error) {
	var total int64
	if err := r.pool.QueryRow(ctx, `SELECT count(*) FROM role`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.pool.Query(ctx, `SELECT id::text, key, title FROM role ORDER BY key LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := make([]Role, 0)
	for rows.Next() {
		var role Role
		if err := rows.Scan(&role.ID, &role.Key, &role.Title); err != nil {
			return nil, 0, err
		}
		items = append(items, role)
	}
	return items, total, rows.Err()
}

func (r *Repository) CreatePermission(ctx context.Context, p *Permission) error {
	query := `INSERT INTO permission (action, resource_kind) VALUES ($1, $2) RETURNING id::text`
	return r.pool.QueryRow(ctx, query, p.Action, p.ResourceKind).Scan(&p.ID)
}

func (r *Repository) UpdatePermission(ctx context.Context, id string, attrs map[string]interface{}) error {
	var current Permission
	row := r.pool.QueryRow(ctx, `SELECT id::text, action, resource_kind FROM permission WHERE id::text=$1`, id)
	if err := row.Scan(&current.ID, &current.Action, &current.ResourceKind); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if v, ok := attrs["action"].(string); ok {
		current.Action = v
	}
	if v, ok := attrs["resource_kind"].(string); ok {
		current.ResourceKind = v
	}
	cmd, err := r.pool.Exec(ctx, `UPDATE permission SET action=$2, resource_kind=$3 WHERE id::text=$1`, id, current.Action, current.ResourceKind)
	if err != nil {
		return err
	}
	if cmd.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *Repository) GetPermission(ctx context.Context, id string) (*Permission, error) {
	var item Permission
	row := r.pool.QueryRow(ctx, `SELECT id::text, action, resource_kind FROM permission WHERE id::text=$1`, id)
	if err := row.Scan(&item.ID, &item.Action, &item.ResourceKind); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &item, nil
}

func (r *Repository) ListPermissions(ctx context.Context, offset, limit int) ([]Permission, int64, error) {
	var total int64
	if err := r.pool.QueryRow(ctx, `SELECT count(*) FROM permission`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.pool.Query(ctx, `SELECT id::text, action, resource_kind FROM permission ORDER BY action, resource_kind LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := make([]Permission, 0)
	for rows.Next() {
		var item Permission
		if err := rows.Scan(&item.ID, &item.Action, &item.ResourceKind); err != nil {
			return nil, 0, err
		}
		items = append(items, item)
	}
	return items, total, rows.Err()
}

// Principal role helpers.
func (r *Repository) AssignPrincipalRole(ctx context.Context, principalID, role string) error {
	roleID, err := r.roleIDByKey(ctx, role)
	if err != nil {
		return err
	}
	return r.withTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM principal_role
			WHERE principal_id=$1 AND principal_kind=$2 AND tenant_id=$3 AND service_id=$4 AND resource_kind=$5 AND resource_id=$6`,
			principalID, string(defaultRoleKind), defaultTenantID, defaultServiceID, defaultScopeKind, defaultResourceID)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO principal_role
			(principal_id, principal_kind, role_id, tenant_id, service_id, resource_kind, resource_id)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			principalID, string(defaultRoleKind), roleID, defaultTenantID, defaultServiceID, defaultScopeKind, defaultResourceID)
		return err
	})
}

func (r *Repository) GetPrincipalRole(ctx context.Context, principalID string) (string, error) {
	var roleKey string
	row := r.pool.QueryRow(ctx, `SELECT r.key
		FROM principal_role pr
		JOIN role r ON r.id = pr.role_id
		WHERE pr.principal_id=$1 AND pr.principal_kind=$2
			AND pr.tenant_id=$3 AND pr.service_id=$4 AND pr.resource_kind=$5 AND pr.resource_id=$6
		LIMIT 1`,
		principalID, string(defaultRoleKind), defaultTenantID, defaultServiceID, defaultScopeKind, defaultResourceID)
	if err := row.Scan(&roleKey); err == nil {
		return roleKey, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}

	row = r.pool.QueryRow(ctx, `SELECT r.key
		FROM principal_role pr
		JOIN role r ON r.id = pr.role_id
		WHERE pr.principal_id=$1 AND pr.principal_kind=$2
		ORDER BY r.key
		LIMIT 1`, principalID, string(defaultRoleKind))
	if err := row.Scan(&roleKey); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	return roleKey, nil
}

// Role permission helpers.
func (r *Repository) AssignPermissionToRole(ctx context.Context, roleKey, permissionID string) error {
	roleID, err := r.roleIDByKey(ctx, roleKey)
	if err != nil {
		return err
	}
	if err := r.ensurePermissionExists(ctx, permissionID); err != nil {
		return err
	}
	_, err = r.pool.Exec(ctx, `INSERT INTO role_permission (role_id, permission_id, resource_id)
		VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, roleID, permissionID, defaultResourceID)
	return err
}

func (r *Repository) ListPermissionsForRole(ctx context.Context, roleKey string) ([]Permission, error) {
	rows, err := r.pool.Query(ctx, `SELECT p.id::text, p.action, p.resource_kind
		FROM role_permission rp
		JOIN role r ON r.id = rp.role_id
		JOIN permission p ON p.id = rp.permission_id
		WHERE r.key=$1
		ORDER BY p.action, p.resource_kind`, roleKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]Permission, 0)
	for rows.Next() {
		var perm Permission
		if err := rows.Scan(&perm.ID, &perm.Action, &perm.ResourceKind); err != nil {
			return nil, err
		}
		items = append(items, perm)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

// PDP contracts implementation for Postgres-backed repository.

// IsSuperAdmin checks if principal is a superadmin.
func (r *Repository) IsSuperAdmin(principalID string, kind model.PrincipalKind) (bool, error) {
	var exists bool
	row := r.pool.QueryRow(context.Background(), `SELECT EXISTS(
		SELECT 1 FROM superadmin_principal WHERE principal_id=$1 AND principal_kind=$2
	)`, principalID, string(kind))
	if err := row.Scan(&exists); err != nil {
		return false, err
	}
	return exists, nil
}

// FindMostSpecificOverride finds the most specific override matching the request.
func (r *Repository) FindMostSpecificOverride(req domainpdp.CheckRequest) (*domainpdp.OverrideMatch, error) {
	rows, err := r.pool.Query(context.Background(), `SELECT
		po.permission_id::text,
		po.effect,
		po.tenant_id::text,
		po.service_id::text,
		po.resource_kind,
		po.resource_id::text,
		p.action,
		p.resource_kind
		FROM principal_override po
		JOIN permission p ON p.id = po.permission_id
		WHERE po.principal_id=$1 AND po.principal_kind=$2`, req.PrincipalID, string(req.PrincipalKind))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var bestMatch *domainpdp.OverrideMatch
	bestScore := -1

	for rows.Next() {
		var permissionID, effect, tenantID, serviceID, resourceKind, resourceID, action, permResourceKind string
		if err := rows.Scan(&permissionID, &effect, &tenantID, &serviceID, &resourceKind, &resourceID, &action, &permResourceKind); err != nil {
			return nil, err
		}
		if action != req.Action || permResourceKind != req.ResourceKind {
			continue
		}
		scope := normalizeScope(tenantID, serviceID, resourceKind, resourceID)
		if !scopeMatchesOverride(scope, req) {
			continue
		}
		score := calculateSpecificity(scope)
		if score > bestScore {
			bestScore = score
			bestMatch = &domainpdp.OverrideMatch{
				Effect:       model.OverrideEffect(effect),
				PermissionID: permissionID,
				Scope:        scope,
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return bestMatch, nil
}

// ResolveRoles returns all roles for a principal with their scopes.
func (r *Repository) ResolveRoles(req domainpdp.CheckRequest) ([]domainpdp.RoleWithScope, error) {
	rows, err := r.pool.Query(context.Background(), `SELECT
		r.id::text,
		r.key,
		pr.tenant_id::text,
		pr.service_id::text,
		pr.resource_kind,
		pr.resource_id::text
		FROM principal_role pr
		JOIN role r ON r.id = pr.role_id
		WHERE pr.principal_id=$1 AND pr.principal_kind=$2`, req.PrincipalID, string(req.PrincipalKind))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	roles := make([]domainpdp.RoleWithScope, 0)
	for rows.Next() {
		var roleID, roleKey, tenantID, serviceID, resourceKind, resourceID string
		if err := rows.Scan(&roleID, &roleKey, &tenantID, &serviceID, &resourceKind, &resourceID); err != nil {
			return nil, err
		}
		scope := normalizeScope(tenantID, serviceID, resourceKind, resourceID)
		if !scopeMatches(scope, req) {
			continue
		}
		roles = append(roles, domainpdp.RoleWithScope{RoleID: roleID, RoleKey: roleKey, Scope: scope})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return roles, nil
}

// ListPermissionsForRoles returns all permissions for given role IDs.
func (r *Repository) ListPermissionsForRoles(roleIDs []string) ([]domainpdp.RolePermissionItem, error) {
	if len(roleIDs) == 0 {
		return nil, nil
	}
	rows, err := r.pool.Query(context.Background(), `SELECT
		rp.role_id::text,
		r.key,
		p.id::text,
		p.action,
		p.resource_kind,
		rp.resource_id::text
		FROM role_permission rp
		JOIN role r ON r.id = rp.role_id
		JOIN permission p ON p.id = rp.permission_id
		WHERE rp.role_id = ANY($1::uuid[])`, roleIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]domainpdp.RolePermissionItem, 0)
	for rows.Next() {
		var roleID, roleKey, permID, action, resourceKind, resourceID string
		if err := rows.Scan(&roleID, &roleKey, &permID, &action, &resourceKind, &resourceID); err != nil {
			return nil, err
		}
		item := domainpdp.RolePermissionItem{
			RoleID:       roleID,
			RoleKey:      roleKey,
			PermissionID: permID,
			Action:       action,
			ResourceKind: resourceKind,
		}
		if resourceID != "" && resourceID != defaultResourceID {
			item.ResourceID = strPtr(resourceID)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

// AddSuperadmin adds a principal to superadmin list (helper for testing/setup).
func (r *Repository) AddSuperadmin(principalID string, kind model.PrincipalKind) {
	_, _ = r.pool.Exec(context.Background(), `INSERT INTO superadmin_principal (principal_id, principal_kind)
		VALUES ($1, $2) ON CONFLICT DO NOTHING`, principalID, string(kind))
}

var (
	ErrNotFound       = errors.New("record not found")
	ErrNotImplemented = errors.New("not implemented")
)

func (r *Repository) roleIDByKey(ctx context.Context, roleKey string) (string, error) {
	var roleID string
	row := r.pool.QueryRow(ctx, `SELECT id::text FROM role WHERE key=$1`, roleKey)
	if err := row.Scan(&roleID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	return roleID, nil
}

func (r *Repository) ensurePermissionExists(ctx context.Context, permissionID string) error {
	var exists bool
	row := r.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM permission WHERE id::text=$1)`, permissionID)
	if err := row.Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	return nil
}

func (r *Repository) withTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func normalizeScope(tenantID, serviceID, resourceKind, resourceID string) domainpdp.OverrideScope {
	return domainpdp.OverrideScope{
		TenantID:     ptrIfNotDefault(tenantID, defaultTenantID),
		ServiceID:    ptrIfNotDefault(serviceID, defaultServiceID),
		ResourceKind: ptrIfNotDefault(resourceKind, defaultScopeKind),
		ResourceID:   ptrIfNotDefault(resourceID, defaultResourceID),
	}
}

func scopeMatchesOverride(scope domainpdp.OverrideScope, req domainpdp.CheckRequest) bool {
	if scope.TenantID != nil {
		if req.TenantID == nil || *scope.TenantID != *req.TenantID {
			return false
		}
	}
	if scope.ServiceID != nil {
		if req.ServiceID == nil || *scope.ServiceID != *req.ServiceID {
			return false
		}
	}
	if scope.ResourceKind != nil {
		if *scope.ResourceKind != req.ResourceKind {
			return false
		}
	}
	if scope.ResourceID != nil {
		if req.ResourceID == nil || *scope.ResourceID != *req.ResourceID {
			return false
		}
	}
	return true
}

func scopeMatches(scope domainpdp.OverrideScope, req domainpdp.CheckRequest) bool {
	if scope.TenantID != nil {
		if req.TenantID == nil || *scope.TenantID != *req.TenantID {
			return false
		}
	}
	if scope.ServiceID != nil {
		if req.ServiceID == nil || *scope.ServiceID != *req.ServiceID {
			return false
		}
	}
	if scope.ResourceKind != nil {
		if *scope.ResourceKind != req.ResourceKind {
			return false
		}
	}
	if scope.ResourceID != nil {
		if req.ResourceID == nil || *scope.ResourceID != *req.ResourceID {
			return false
		}
	}
	return true
}

func calculateSpecificity(scope domainpdp.OverrideScope) int {
	score := 0
	if scope.TenantID != nil {
		score += 1000
	}
	if scope.ServiceID != nil {
		score += 100
	}
	if scope.ResourceKind != nil {
		score += 10
	}
	if scope.ResourceID != nil {
		score += 1
	}
	return score
}

func ptrIfNotDefault(value, defaultValue string) *string {
	if value == "" || value == defaultValue {
		return nil
	}
	v := value
	return &v
}

func strPtr(value string) *string {
	v := value
	return &v
}
