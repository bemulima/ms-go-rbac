package repo

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PermissionRepository provides CRUD access to permissions.
type PermissionRepository struct {
	pool *pgxpool.Pool
}

func NewPermissionRepository(pool *pgxpool.Pool) *PermissionRepository {
	return &PermissionRepository{pool: pool}
}

func (r *PermissionRepository) Create(ctx context.Context, perm *Permission) error {
	query := `INSERT INTO permission (action, resource_kind) VALUES ($1, $2) RETURNING id::text`
	return r.pool.QueryRow(ctx, query, perm.Action, perm.ResourceKind).Scan(&perm.ID)
}

func (r *PermissionRepository) Update(ctx context.Context, id string, attrs map[string]interface{}) error {
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

func (r *PermissionRepository) Get(ctx context.Context, id string) (*Permission, error) {
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

func (r *PermissionRepository) List(ctx context.Context, offset, limit int) ([]Permission, int64, error) {
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

func (r *PermissionRepository) Delete(ctx context.Context, id string) error {
	cmd, err := r.pool.Exec(ctx, `DELETE FROM permission WHERE id::text=$1`, id)
	if err != nil {
		return err
	}
	if cmd.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
