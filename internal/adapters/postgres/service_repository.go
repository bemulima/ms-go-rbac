package repo

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ServiceRepository provides CRUD access to services.
type ServiceRepository struct {
	pool *pgxpool.Pool
}

func NewServiceRepository(pool *pgxpool.Pool) *ServiceRepository {
	return &ServiceRepository{pool: pool}
}

func (r *ServiceRepository) Create(ctx context.Context, service *Service) error {
	query := `INSERT INTO service (key, title) VALUES ($1, $2) RETURNING id::text`
	return r.pool.QueryRow(ctx, query, service.Key, service.Title).Scan(&service.ID)
}

func (r *ServiceRepository) Update(ctx context.Context, id, title string) error {
	cmd, err := r.pool.Exec(ctx, `UPDATE service SET title=$2 WHERE id::text=$1`, id, title)
	if err != nil {
		return err
	}
	if cmd.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *ServiceRepository) Get(ctx context.Context, id string) (*Service, error) {
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

func (r *ServiceRepository) List(ctx context.Context, offset, limit int) ([]Service, int64, error) {
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

func (r *ServiceRepository) Delete(ctx context.Context, id string) error {
	cmd, err := r.pool.Exec(ctx, `DELETE FROM service WHERE id::text=$1`, id)
	if err != nil {
		return err
	}
	if cmd.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
