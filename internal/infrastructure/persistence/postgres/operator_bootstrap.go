package repo

import (
	"context"
	"errors"
	"fmt"
	"github.com/example/ms-rbac-service/internal/domain/repository"
	"github.com/jackc/pgx/v5"
)

// Bootstrap commits grant and immutable receipt together. The global lock serializes
// competing initial operator invocations, while the unique principal prevents reparenting.
func (r *PrincipalRoleRepository) Bootstrap(ctx context.Context, in repository.OperatorBootstrap) (out repository.BootstrapReceipt, err error) {
	err = withTx(ctx, r.pool, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtext('rbac-operator-bootstrap'))"); e != nil {
			return e
		}
		// Share the principal lock with signed signup; neither path may race a grant.
		if _, e := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "rbac-signup:"+in.PrincipalID); e != nil {
			return e
		}
		var old repository.BootstrapReceipt
		e := tx.QueryRow(ctx, `SELECT request_id::text,principal_id::text,role_key,expected_role,operator_name,environment,to_char(applied_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') FROM operator_bootstrap_receipt WHERE request_id=$1`, in.RequestID).Scan(&old.RequestID, &old.PrincipalID, &old.Role, &old.ExpectedRole, &old.Operator, &old.Environment, &old.AppliedAt)
		if e == nil {
			if old.OperatorBootstrap != in {
				return errors.New("bootstrap intent conflict")
			}
			// A receipt is not permission to silently repair a later changed assignment.
			var current string
			if e = tx.QueryRow(ctx, `WITH locked_roles AS (SELECT r.key FROM principal_role p JOIN role r ON r.id=p.role_id WHERE p.principal_id=$1 AND p.principal_kind=$2 AND p.tenant_id=$3 AND p.service_id=$4 AND p.resource_kind=$5 AND p.resource_id=$6 FOR UPDATE OF p) SELECT coalesce(string_agg(key,',' ORDER BY key),'') FROM locked_roles`, in.PrincipalID, string(defaultRoleKind), defaultTenantID, defaultServiceID, defaultScopeKind, defaultResourceID).Scan(&current); e != nil {
				return e
			}
			if current != in.Role {
				return errors.New("bootstrap assignment drift")
			}
			out = old
			return nil
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		var current string
		e = tx.QueryRow(ctx, `WITH locked_roles AS (SELECT r.key FROM principal_role p JOIN role r ON r.id=p.role_id WHERE p.principal_id=$1 AND p.principal_kind=$2 AND p.tenant_id=$3 AND p.service_id=$4 AND p.resource_kind=$5 AND p.resource_id=$6 FOR UPDATE OF p) SELECT coalesce(string_agg(key,',' ORDER BY key),'') FROM locked_roles`, in.PrincipalID, string(defaultRoleKind), defaultTenantID, defaultServiceID, defaultScopeKind, defaultResourceID).Scan(&current)
		if e != nil {
			return e
		}
		if current != in.ExpectedRole {
			return errors.New("bootstrap expected role conflict")
		}
		var roleID string
		if e = tx.QueryRow(ctx, "SELECT id::text FROM role WHERE key=$1", in.Role).Scan(&roleID); e != nil {
			return e
		}
		if e = replacePrincipalRole(ctx, tx, in.PrincipalID, roleID); e != nil {
			return e
		}
		out.OperatorBootstrap = in
		e = tx.QueryRow(ctx, `INSERT INTO operator_bootstrap_receipt (request_id,principal_id,role_key,expected_role,operator_name,environment) VALUES ($1,$2,$3,$4,$5,$6) RETURNING to_char(applied_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`, in.RequestID, in.PrincipalID, in.Role, in.ExpectedRole, in.Operator, in.Environment).Scan(&out.AppliedAt)
		return e
	})
	if err != nil {
		return repository.BootstrapReceipt{}, fmt.Errorf("operator transaction failed: %w", err)
	}
	return out, nil
}
