package repo

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RoleRepository provides CRUD access to roles.
type RoleRepository struct {
	pool *pgxpool.Pool
}

func NewRoleRepository(pool *pgxpool.Pool) *RoleRepository {
	return &RoleRepository{pool: pool}
}

func (r *RoleRepository) Create(ctx context.Context, role *Role) error {
	query := `INSERT INTO role (key, title) VALUES ($1, $2) RETURNING id::text`
	return r.pool.QueryRow(ctx, query, role.Key, role.Title).Scan(&role.ID)
}

func (r *RoleRepository) Update(ctx context.Context, id, title string) error {
	cmd, err := r.pool.Exec(ctx, `UPDATE role SET title=$2 WHERE id::text=$1`, id, title)
	if err != nil {
		return err
	}
	if cmd.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *RoleRepository) Get(ctx context.Context, id string) (*Role, error) {
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

func (r *RoleRepository) List(ctx context.Context, offset, limit int) ([]Role, int64, error) {
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

func (r *RoleRepository) Delete(ctx context.Context, id string) error {
	cmd, err := r.pool.Exec(ctx, `DELETE FROM role WHERE id::text=$1`, id)
	if err != nil {
		return err
	}
	if cmd.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
