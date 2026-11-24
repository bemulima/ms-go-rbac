package repo

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/example/ms-rbac-service/internal/domain"
	"github.com/jackc/pgx/v5"
)

// In-memory transaction protocol only: SQL execution/migration evidence is
// intentionally reserved for a separately authorized disposable database.
type mcpMentorReadDB struct {
	base            *mentorReadbackDBFixture
	permission      bool
	failPermission  bool
	permissionReads int
}
type mcpMentorReadTx struct {
	pgx.Tx
	db         *mcpMentorReadDB
	permission bool
}

func (db *mcpMentorReadDB) BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error) {
	tx, err := db.base.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &mcpMentorReadTx{Tx: tx, db: db, permission: db.permission}, nil
}
func (tx *mcpMentorReadTx) QueryRow(ctx context.Context, query string, args ...any) pgx.Row {
	if strings.Contains(query, "public.role_permission") {
		tx.db.permissionReads++
		if tx.db.failPermission {
			return mentorStoreRow{err: errors.New("private SQL diagnostic")}
		}
		if len(args) != 3 || args[0] != tx.db.base.state.roleID || args[1] != defaultResourceID || args[2] != domain.MCPMentorProfilePermission || !strings.Contains(query, "public.mcp_mentor_profile_permission") || !strings.Contains(query, "p.resource_kind=''") {
			return mentorStoreRow{err: errors.New("escaped exact Mentor permission")}
		}
		return mentorStoreRow{values: []any{tx.permission}}
	}
	return tx.Tx.QueryRow(ctx, query, args...)
}
func TestMCPMentorAccessRequiresCurrentScopedRoleAndExplicitPermission(t *testing.T) {
	command := mentorStoreProof("APPROVE", 2).Command
	for _, test := range []struct {
		name                 string
		approved, permission bool
		expected             domain.MCPMentorAccess
	}{
		{"unapproved with permission", false, true, domain.MCPMentorAccess{}},
		{"role without permission", true, false, domain.MCPMentorAccess{Active: true}},
		{"approved with explicit permission", true, true, domain.MCPMentorAccess{Active: true, Allowed: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			base := newMentorReadbackDBFixture()
			if test.approved {
				base.current(command)
			}
			db := &mcpMentorReadDB{base: base, permission: test.permission}
			result, err := NewMCPMentorAccessReader(db).ReadMCPMentorAccess(context.Background(), command.TargetUserID)
			if err != nil || result != test.expected || base.badProtocol || base.commitCount != 1 || base.rollbackCount != 0 {
				t.Fatalf("result=%+v err=%v protocol=%v", result, err, base.badProtocol)
			}
			if !test.approved && db.permissionReads != 0 {
				t.Fatal("permission evaluated without role")
			}
		})
	}
	base := newMentorReadbackDBFixture()
	base.current(command)
	base.current(mentorStoreProof("SUSPEND", 3).Command)
	db := &mcpMentorReadDB{base: base, permission: true}
	result, err := NewMCPMentorAccessReader(db).ReadMCPMentorAccess(context.Background(), command.TargetUserID)
	if err != nil || result.Active || result.Allowed || db.permissionReads != 0 {
		t.Fatal("historical approval survived current suspension")
	}
}
func TestMCPMentorAccessCorruptionAndDependencyErrorsWithholdAuthority(t *testing.T) {
	command := mentorStoreProof("APPROVE", 2).Command
	for _, test := range []struct {
		name string
		edit func(*mcpMentorReadDB)
	}{
		{"metadata drift", func(db *mcpMentorReadDB) { db.base.state.scopeValid = 0 }},
		{"dangling receipt", func(db *mcpMentorReadDB) { delete(db.base.state.receipts, command.RequestID) }},
		{"lost physical role", func(db *mcpMentorReadDB) { delete(db.base.state.physical, command.TargetUserID) }},
		{"permission outage", func(db *mcpMentorReadDB) { db.failPermission = true }},
		{"commit outage", func(db *mcpMentorReadDB) { db.base.failAt = "commit" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			base := newMentorReadbackDBFixture()
			base.current(command)
			db := &mcpMentorReadDB{base: base, permission: true}
			test.edit(db)
			result, err := NewMCPMentorAccessReader(db).ReadMCPMentorAccess(context.Background(), command.TargetUserID)
			if err != domain.ErrAuthorityUnavailable || result != (domain.MCPMentorAccess{}) || base.rollbackCount != 1 {
				t.Fatalf("unsafe snapshot authorized: %+v %v", result, err)
			}
		})
	}
}
