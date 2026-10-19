package lc07b0_test

import (
	"context"
	"testing"
	"time"
)

func TestProvisionDisposableRoles(t *testing.T) {
	dir, m, c, digest := load(t)
	conn := openOwned(t, m, c, digest)
	defer conn.Close(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	tx, e := conn.Begin(ctx)
	if e != nil {
		t.Fatal("owner transaction unavailable")
	}
	defer tx.Rollback(ctx)
	fail := func() { t.Fatal("immutable fixture role conflict") }
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, digest); e != nil {
		fail()
	}
	// Existing canonical global/core scope; only three closed negative/positive actors.
	const core = "00000000-0000-0000-0000-000000000100"
	const zero = "00000000-0000-0000-0000-000000000000"
	if _, e = tx.Exec(ctx, `INSERT INTO service(id,key,title) VALUES($1,'core','Core Service') ON CONFLICT DO NOTHING`, core); e != nil {
		fail()
	}
	var serviceKey string
	if e = tx.QueryRow(ctx, `SELECT key FROM service WHERE id=$1`, core).Scan(&serviceKey); e != nil || serviceKey != "core" {
		fail()
	}
	var serviceID string
	if e = tx.QueryRow(ctx, `SELECT id::text FROM service WHERE key='core'`).Scan(&serviceID); e != nil || serviceID != core {
		fail()
	}
	for _, actor := range []string{"admin", "student", "teacher"} {
		id, _ := identity(m.Run, actor)
		var roleID string
		if _, e = tx.Exec(ctx, `INSERT INTO role(key,title) VALUES($1,$1) ON CONFLICT DO NOTHING`, actor); e != nil {
			fail()
		}
		if e = tx.QueryRow(ctx, `SELECT id::text FROM role WHERE key=$1`, actor).Scan(&roleID); e != nil {
			fail()
		}
		var count int
		if e = tx.QueryRow(ctx, `SELECT count(*) FROM principal_role WHERE principal_id=$1`, id).Scan(&count); e != nil {
			fail()
		}
		if count == 0 {
			if _, e = tx.Exec(ctx, `INSERT INTO principal_role(principal_id,principal_kind,role_id,tenant_id,service_id,resource_kind,resource_id) VALUES($1,'user',$2,$3,$4,'global',$3)`, id, roleID, zero, core); e != nil {
				fail()
			}
		}
		var exact int
		if e = tx.QueryRow(ctx, `SELECT count(*) FROM principal_role WHERE principal_id=$1 AND principal_kind='user' AND role_id=$2 AND tenant_id=$3 AND service_id=$4 AND resource_kind='global' AND resource_id=$3`, id, roleID, zero, core).Scan(&exact); e != nil || exact != 1 || count > 1 {
			fail()
		}
	}
	if e = tx.Commit(ctx); e != nil {
		fail()
	}
	receipt(t, dir, "rbac", digest, m)
}
