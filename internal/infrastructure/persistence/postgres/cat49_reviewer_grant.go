package repo

import (
	"context"
	"errors"
	"fmt"

	"github.com/example/ms-rbac-service/internal/domain/repository"
	"github.com/jackc/pgx/v5"
)

// GrantCAT49Reviewer belongs only to the separate, task-owned operator. It
// never changes the canonical lw_rbac bootstrap guard or opens an HTTP route.
func (r *PrincipalRoleRepository) GrantCAT49Reviewer(ctx context.Context,
	in repository.CAT49ReviewerGrantIntent) (out repository.CAT49ReviewerGrantReceipt,err error) {
	err = withTx(ctx,r.pool,func(tx pgx.Tx) error {
		if _,e:=tx.Exec(ctx,"SELECT pg_advisory_xact_lock(hashtext('cat49-reviewer-grant'))");e!=nil {return e}
		if _,e:=tx.Exec(ctx,"SELECT pg_advisory_xact_lock(hashtextextended($1,0))","rbac-signup:"+in.PrincipalID);e!=nil {return e}
		var old repository.CAT49ReviewerGrantReceipt
		e:=tx.QueryRow(ctx,"SELECT run_id,request_id::text,principal_id::text,auth_receipt_digest,operator_name,to_char(applied_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') FROM cat49_disposable_reviewer_grant WHERE request_id=$1",in.RequestID).
			Scan(&old.RunID,&old.RequestID,&old.PrincipalID,&old.AuthReceiptDigest,&old.Operator,&old.AppliedAt)
		if e==nil {
			if old.RunID!=in.RunID || old.PrincipalID!=in.PrincipalID || old.AuthReceiptDigest!=in.AuthReceiptDigest || old.Operator!=in.Operator {
				return errors.New("reviewer grant replay conflict")
			}
			var current string
			if e=tx.QueryRow(ctx,"SELECT coalesce(string_agg(r.key,',' ORDER BY r.key),'') FROM principal_role p JOIN role r ON r.id=p.role_id WHERE p.principal_id=$1",in.PrincipalID).Scan(&current);e!=nil {return e}
			if current!="moderator" {return errors.New("reviewer grant role drift")}
			out=old
			out.Schema="cat49-disposable-reviewer-grant.v1"
			out.Role="moderator"
			return nil
		}
		if !errors.Is(e,pgx.ErrNoRows) {return e}
		// Exactly one new reviewer per disposable run, no takeover of another
		// principal, and no promotion of an already existing Student identity.
		var exists bool
		if e=tx.QueryRow(ctx,"SELECT EXISTS(SELECT 1 FROM cat49_disposable_reviewer_grant WHERE run_id=$1 OR principal_id=$2)",in.RunID,in.PrincipalID).Scan(&exists);e!=nil {return e}
		if exists {return errors.New("reviewer grant already allocated")}
		var count int64
		if e=tx.QueryRow(ctx,"SELECT count(*) FROM principal_role WHERE principal_id=$1",in.PrincipalID).Scan(&count);e!=nil {return e}
		if count!=0 {return errors.New("reviewer principal already has roles")}
		var roleID string
		if e=tx.QueryRow(ctx,"SELECT id::text FROM role WHERE key='moderator' FOR KEY SHARE").Scan(&roleID);e!=nil {return e}
		if _,e=tx.Exec(ctx,"INSERT INTO principal_role (principal_id,principal_kind,role_id,tenant_id,service_id,resource_kind,resource_id) VALUES ($1,$2,$3,$4,$5,$6,$7)",
			in.PrincipalID,string(defaultRoleKind),roleID,defaultTenantID,defaultServiceID,defaultScopeKind,defaultResourceID);e!=nil {return e}
		out=repository.CAT49ReviewerGrantReceipt{
			Schema:"cat49-disposable-reviewer-grant.v1",RunID:in.RunID,
			RequestID:in.RequestID,PrincipalID:in.PrincipalID,
			AuthReceiptDigest:in.AuthReceiptDigest,Role:"moderator",Operator:in.Operator,
		}
		e=tx.QueryRow(ctx,"INSERT INTO cat49_disposable_reviewer_grant (run_id,request_id,principal_id,auth_receipt_digest,operator_name) VALUES ($1,$2,$3,$4,$5) RETURNING to_char(applied_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')",
			in.RunID,in.RequestID,in.PrincipalID,in.AuthReceiptDigest,in.Operator).Scan(&out.AppliedAt)
		return e
	})
	if err!=nil {return repository.CAT49ReviewerGrantReceipt{},fmt.Errorf("CAT49 reviewer grant denied: %w",err)}
	return out,nil
}
