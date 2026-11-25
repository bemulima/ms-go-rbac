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
	offers          bool
	skillDraft      bool
	workspaceScope  string
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
		action := domain.MCPMentorProfilePermission
		marker := "public.mcp_mentor_profile_permission"
		if tx.db.offers {
			action = domain.MCPMentorOffersPermission
			marker = "public.mcp_mentor_offers_permission"
		} else if tx.db.skillDraft {
			action = domain.MCPMentorSkillDraftPermission
			marker = "public.mcp_mentor_skill_draft_permission"
		}
		expectedArgs := 3
		if tx.db.workspaceScope != "" {
			expectedArgs = 4
			action = "mcp.mentor.cohorts.read"
			marker = "public.mcp_mentor_workspace_read_permission"
			if len(args) != expectedArgs || args[3] != tx.db.workspaceScope || !strings.Contains(query, "marker.scope=$4") {
				return mentorStoreRow{err: errors.New("missing exact workspace scope binding")}
			}
		}
		if len(args) != expectedArgs || args[0] != tx.db.base.state.roleID || args[1] != defaultResourceID || args[2] != action || !strings.Contains(query, marker) || !strings.Contains(query, "p.resource_kind=''") {
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
			result, err := NewMCPMentorAccessReader(db).ReadMCPMentorAccess(context.Background(), command.TargetUserID, domain.MCPMentorProfileScope)
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
	result, err := NewMCPMentorAccessReader(db).ReadMCPMentorAccess(context.Background(), command.TargetUserID, domain.MCPMentorProfileScope)
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
			result, err := NewMCPMentorAccessReader(db).ReadMCPMentorAccess(context.Background(), command.TargetUserID, domain.MCPMentorProfileScope)
			if err != domain.ErrAuthorityUnavailable || result != (domain.MCPMentorAccess{}) || base.rollbackCount != 1 {
				t.Fatalf("unsafe snapshot authorized: %+v %v", result, err)
			}
		})
	}
}

func TestMCPMentorOffersChecksOnlyItsMarkedPermission(t *testing.T) {
	command := mentorStoreProof("APPROVE", 2).Command
	base := newMentorReadbackDBFixture()
	base.current(command)
	db := &mcpMentorReadDB{base: base, offers: true}
	result, err := NewMCPMentorAccessReader(db).ReadMCPMentorAccess(context.Background(), command.TargetUserID, domain.MCPMentorOffersScope)
	if err != nil || !result.Active || result.Allowed || db.permissionReads != 1 {
		t.Fatalf("profile permission substituted for offers: %+v %v", result, err)
	}
}

func TestMCPMentorWorkspacePermissionUsesExactMarkerScope(t *testing.T) {
	command := mentorStoreProof("APPROVE", 2).Command
	for _, assigned := range []bool{false, true} {
		base := newMentorReadbackDBFixture()
		base.current(command)
		scope := "mentor:cohorts:read"
		db := &mcpMentorReadDB{base: base, workspaceScope: scope, permission: assigned}
		result, err := NewMCPMentorAccessReader(db).ReadMCPMentorAccess(context.Background(), command.TargetUserID, scope)
		if err != nil || !result.Active || result.Allowed != assigned || db.permissionReads != 1 || base.commitCount != 1 {
			t.Fatalf("workspace scope changed explicit permission: %+v %v", result, err)
		}
	}
}

func TestMCPMentorSkillDraftPermissionIsExplicit(t *testing.T) {
	command := mentorStoreProof("APPROVE", 2).Command
	for _, assigned := range []bool{false, true} {
		base := newMentorReadbackDBFixture()
		base.current(command)
		db := &mcpMentorReadDB{base: base, skillDraft: true, permission: assigned}
		result, err := NewMCPMentorAccessReader(db).ReadMCPMentorAccess(context.Background(), command.TargetUserID, domain.MCPMentorSkillDraftScope)
		if err != nil || !result.Active || result.Allowed != assigned || db.permissionReads != 1 || base.commitCount != 1 {
			t.Fatalf("draft permission decision disagreed with its explicit marker: %+v %v", result, err)
		}
	}
}
