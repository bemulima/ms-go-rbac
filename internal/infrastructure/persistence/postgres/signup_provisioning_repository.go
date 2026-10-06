package repo

import (
	"context"
	"errors"

	"github.com/example/ms-rbac-service/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SignupProvisioningRepository struct{ pool *pgxpool.Pool }

func NewSignupProvisioningRepository(pool *pgxpool.Pool) *SignupProvisioningRepository {
	return &SignupProvisioningRepository{pool: pool}
}

func (r *SignupProvisioningRepository) ProvisionSignup(ctx context.Context, grant domain.SignupGrant) error {
	if !domain.ValidSignupIdentity(grant, grant.Subject) {
		return domain.ErrUnauthenticated
	}
	if !domain.ValidSignupBinding(grant, grant.Subject) {
		return domain.ErrSignupConflict
	}
	if r == nil || r.pool == nil {
		return domain.ErrAuthorityUnavailable
	}
	err := withTx(ctx, r.pool, func(tx pgx.Tx) error {
		// The UUID was canonicalized by admission, so equivalent principals use
		// the same transaction lock. All signup writes share this lock.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "rbac-signup:"+grant.PrincipalID); err != nil {
			return err
		}
		var receipt domain.SignupGrant
		err := tx.QueryRow(ctx, `SELECT principal_id::text, role_key, principal_kind,
			tenant_id::text, service_id::text, resource_kind, resource_id::text
			FROM signup_provisioning_receipt WHERE issuer=$1 AND operation_id=$2`,
			grant.Issuer, grant.OperationID).Scan(&receipt.PrincipalID, &receipt.Role, &receipt.PrincipalKind,
			&receipt.TenantID, &receipt.ServiceID, &receipt.ResourceKind, &receipt.ResourceID)
		if err == nil {
			if receipt.PrincipalID != grant.PrincipalID || receipt.Role != grant.Role || receipt.PrincipalKind != grant.PrincipalKind ||
				receipt.TenantID != grant.TenantID || receipt.ServiceID != grant.ServiceID ||
				receipt.ResourceKind != grant.ResourceKind || receipt.ResourceID != grant.ResourceID {
				return domain.ErrSignupConflict
			}
			return nil // Authorization has already run; stable replay performs no writes.
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var existingOperation string
		err = tx.QueryRow(ctx, `SELECT operation_id::text FROM signup_provisioning_receipt
			WHERE issuer=$1 AND principal_id=$2`, grant.Issuer, grant.PrincipalID).Scan(&existingOperation)
		if err == nil {
			return domain.ErrSignupConflict
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		// No cross-scope fallback: the accepted flow owns exactly this tuple.
		var total, student int64
		if err := tx.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE r.key=$7)
			FROM principal_role pr JOIN role r ON r.id=pr.role_id
			WHERE pr.principal_id=$1 AND pr.principal_kind=$2 AND pr.tenant_id=$3
			AND pr.service_id=$4 AND pr.resource_kind=$5 AND pr.resource_id=$6`,
			grant.PrincipalID, grant.PrincipalKind, grant.TenantID, grant.ServiceID, grant.ResourceKind, grant.ResourceID, grant.Role).Scan(&total, &student); err != nil {
			return err
		}
		if total > 0 && (total != 1 || student != 1) {
			return domain.ErrSignupConflict
		}
		if total == 0 {
			var roleID string
			if err := tx.QueryRow(ctx, `SELECT id::text FROM role WHERE key=$1 FOR KEY SHARE`, grant.Role).Scan(&roleID); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO principal_role
				(principal_id,principal_kind,role_id,tenant_id,service_id,resource_kind,resource_id)
				VALUES($1,$2,$3,$4,$5,$6,$7)`, grant.PrincipalID, grant.PrincipalKind, roleID,
				grant.TenantID, grant.ServiceID, grant.ResourceKind, grant.ResourceID); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, `INSERT INTO signup_provisioning_receipt
			(issuer,operation_id,principal_id,role_key,principal_kind,tenant_id,service_id,resource_kind,resource_id)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, grant.Issuer, grant.OperationID, grant.PrincipalID,
			grant.Role, grant.PrincipalKind, grant.TenantID, grant.ServiceID, grant.ResourceKind, grant.ResourceID)
		return err
	})
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) && postgresError.Code == "23505" {
		return domain.ErrSignupConflict
	}
	return err
}
