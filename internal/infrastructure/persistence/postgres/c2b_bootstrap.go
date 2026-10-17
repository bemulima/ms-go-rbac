package repo

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/example/ms-rbac-service/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type C2BBootstrapRepository struct{ Pool *pgxpool.Pool }

func (r C2BBootstrapRepository) ApplyC2B(ctx context.Context, i domain.C2BIntent) (domain.C2BReceipt, error) {
	out := domain.C2BReceiptFor(i)
	if !i.Valid() {
		return out, errors.New("invalid intent")
	}
	tx, e := r.Pool.Begin(ctx)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	var db, user string
	if e = tx.QueryRow(ctx, "SELECT current_database(),current_user").Scan(&db, &user); e != nil || db != "c2b_rbac_20261016" || user != "c2b_rbac_fixture" {
		return out, errors.New("isolated bootstrap database denied")
	}
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", "c2b-role:"+i.Principal); e != nil {
		return out, e
	}
	var raw []byte
	e = tx.QueryRow(ctx, "SELECT receipt_json FROM c2b_rbac_bootstrap_audit WHERE operation_id=$1", i.Operation).Scan(&raw)
	if e == nil {
		var old domain.C2BReceipt
		if json.Unmarshal(raw, &old) != nil || old != out {
			return out, errors.New("immutable role receipt conflict")
		}
		var role string
		e = tx.QueryRow(ctx, "SELECT r.key FROM principal_role p JOIN role r ON r.id=p.role_id WHERE p.principal_id=$1 AND p.principal_kind='user' AND p.tenant_id=$2 AND p.service_id=$3 AND p.resource_kind='global' AND p.resource_id=$2", i.Principal, SignupZero, SignupCore).Scan(&role)
		if e != nil || role != i.Role {
			return out, errors.New("assignment no longer matches receipt")
		}
		return out, tx.Commit(ctx)
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return out, e
	}
	var count int
	if e = tx.QueryRow(ctx, "SELECT count(*) FROM principal_role WHERE principal_id=$1", i.Principal).Scan(&count); e != nil || count != 0 {
		return out, errors.New("existing role cannot be adopted or upgraded")
	}
	if i.Role == "mentor" {
		if _, e = tx.Exec(ctx, "INSERT INTO role(key,title) VALUES('mentor','C2-B isolated Mentor') ON CONFLICT(key) DO NOTHING"); e != nil {
			return out, e
		}
	}
	var roleID, title string
	if e = tx.QueryRow(ctx, "SELECT id::text,title FROM role WHERE key=$1", i.Role).Scan(&roleID, &title); e != nil {
		return out, e
	}
	if i.Role == "mentor" && title != "C2-B isolated Mentor" {
		return out, errors.New("conflicting mentor definition")
	}
	if _, e = tx.Exec(ctx, "INSERT INTO principal_role(principal_id,principal_kind,role_id,tenant_id,service_id,resource_kind,resource_id) VALUES($1,'user',$2,$3,$4,'global',$3)", i.Principal, roleID, SignupZero, SignupCore); e != nil {
		return out, e
	}
	raw, _ = json.Marshal(out)
	if _, e = tx.Exec(ctx, "INSERT INTO c2b_rbac_bootstrap_audit(operation_id,principal_id,receipt_json) VALUES($1,$2,$3::jsonb)", i.Operation, i.Principal, raw); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}

const SignupZero = "00000000-0000-0000-0000-000000000000"
const SignupCore = "00000000-0000-0000-0000-000000000100"
