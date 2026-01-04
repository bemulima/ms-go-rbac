package repo

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RolePermissionCreate describes a role-permission assignment request.
type RolePermissionCreate struct {
	RoleKey      string
	PermissionID string
}

// RolePermissionRepository manages role-permission assignments.
type RolePermissionRepository struct {
	pool *pgxpool.Pool
}

func NewRolePermissionRepository(pool *pgxpool.Pool) *RolePermissionRepository {
	return &RolePermissionRepository{pool: pool}
}

func (r *RolePermissionRepository) Create(ctx context.Context, input RolePermissionCreate) error {
	roleID, err := roleIDByKey(ctx, r.pool, input.RoleKey)
	if err != nil {
		return err
	}
	if err := ensurePermissionExists(ctx, r.pool, input.PermissionID); err != nil {
		return err
	}
	_, err = r.pool.Exec(ctx, `INSERT INTO role_permission (role_id, permission_id, resource_id)
		VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, roleID, input.PermissionID, defaultResourceID)
	return err
}

func (r *RolePermissionRepository) ListByRoleKey(ctx context.Context, roleKey string) ([]Permission, error) {
	rows, err := r.pool.Query(ctx, `SELECT
		p.id::text,
		p.action,
		p.resource_kind
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
