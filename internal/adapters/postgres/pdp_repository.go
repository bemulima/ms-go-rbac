package repo

import (
	"context"

	"github.com/example/ms-rbac-service/internal/domain/model"
	domainpdp "github.com/example/ms-rbac-service/internal/domain/pdp"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PDPRepository provides data access for policy decisions.
type PDPRepository struct {
	pool *pgxpool.Pool
}

func NewPDPRepository(pool *pgxpool.Pool) *PDPRepository {
	return &PDPRepository{pool: pool}
}

// GetByPrincipal returns true when a principal is marked as superadmin.
func (r *PDPRepository) GetByPrincipal(ctx context.Context, principalID string, kind model.PrincipalKind) (bool, error) {
	var exists bool
	row := r.pool.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM superadmin_principal WHERE principal_id=$1 AND principal_kind=$2
	)`, principalID, string(kind))
	if err := row.Scan(&exists); err != nil {
		return false, err
	}
	return exists, nil
}

// GetByRequest finds the most specific override matching the request.
func (r *PDPRepository) GetByRequest(ctx context.Context, req domainpdp.CheckRequest) (*domainpdp.OverrideMatch, error) {
	rows, err := r.pool.Query(ctx, `SELECT
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

// List returns all roles for a principal with their scopes.
func (r *PDPRepository) List(ctx context.Context, req domainpdp.CheckRequest) ([]domainpdp.RoleWithScope, error) {
	rows, err := r.pool.Query(ctx, `SELECT
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

// ListByRoleIDs returns all permissions for given role IDs.
func (r *PDPRepository) ListByRoleIDs(ctx context.Context, roleIDs []string) ([]domainpdp.RolePermissionItem, error) {
	if len(roleIDs) == 0 {
		return nil, nil
	}
	rows, err := r.pool.Query(ctx, `SELECT
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
