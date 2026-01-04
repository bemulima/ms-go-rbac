package repo

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PrincipalRoleUpdate contains fields for updating a principal role.
type PrincipalRoleUpdate struct {
	RoleKey string
}

// PrincipalRoleRepository manages role assignments for principals.
type PrincipalRoleRepository struct {
	pool *pgxpool.Pool
}

func NewPrincipalRoleRepository(pool *pgxpool.Pool) *PrincipalRoleRepository {
	return &PrincipalRoleRepository{pool: pool}
}

func (r *PrincipalRoleRepository) Update(ctx context.Context, principalID string, input PrincipalRoleUpdate) error {
	roleID, err := roleIDByKey(ctx, r.pool, input.RoleKey)
	if err != nil {
		return err
	}
	return withTx(ctx, r.pool, func(tx pgx.Tx) error {
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

func (r *PrincipalRoleRepository) Get(ctx context.Context, principalID string) (string, error) {
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
