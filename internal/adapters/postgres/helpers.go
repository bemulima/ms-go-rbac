package repo

import (
	"context"
	"errors"

	"github.com/example/ms-rbac-service/internal/domain/model"
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

func roleIDByKey(ctx context.Context, pool *pgxpool.Pool, roleKey string) (string, error) {
	var roleID string
	row := pool.QueryRow(ctx, `SELECT id::text FROM role WHERE key=$1`, roleKey)
	if err := row.Scan(&roleID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	return roleID, nil
}

func ensurePermissionExists(ctx context.Context, pool *pgxpool.Pool, permissionID string) error {
	var exists bool
	row := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM permission WHERE id::text=$1)`, permissionID)
	if err := row.Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	return nil
}

func withTx(ctx context.Context, pool *pgxpool.Pool, fn func(pgx.Tx) error) error {
	tx, err := pool.Begin(ctx)
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
