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
	taskAssignmentScope     string
	dialogWrite             bool
	studentFeedback         bool
	cohortRespond           bool
	offers                  bool
	skillDraft              bool
	workspaceScope          string
	authoringScope          string
	authoringAction         string
	managementScope         string
	finalScope, finalAction string
	base                    *mentorReadbackDBFixture
	permission              bool
	failPermission          bool
	permissionReads         int
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
		} else if tx.db.cohortRespond {
			action = domain.MCPMentorCohortRespondAction
			marker = "public.mcp_mentor_cohort_response_permission"
		} else if tx.db.dialogWrite {
			action = domain.MCPMentorDialogWriteAction
			marker = "public.mcp_mentor_dialog_write_permission"
		} else if tx.db.studentFeedback {
			action = domain.MCPMentorStudentFeedbackAction
			marker = "public.mcp_mentor_student_feedback_permission"
		}
		expectedArgs := 3
		if tx.db.taskAssignmentScope != "" {
			expectedArgs = 4
			action = domain.MCPMentorTaskAssignmentAction(tx.db.taskAssignmentScope)
			marker = "public.mcp_mentor_task_assignment_permission"
			if len(args) != expectedArgs || args[3] != tx.db.taskAssignmentScope || !strings.Contains(query, "marker.scope=$4") {
				return mentorStoreRow{err: errors.New("missing exact task assignment scope binding")}
			}
		}
		if tx.db.workspaceScope != "" {
			expectedArgs = 4
			action = domain.MCPMentorWorkspaceReadAction(tx.db.workspaceScope)
			marker = "public.mcp_mentor_workspace_read_permission"
			if len(args) != expectedArgs || args[3] != tx.db.workspaceScope || !strings.Contains(query, "marker.scope=$4") {
				return mentorStoreRow{err: errors.New("missing exact workspace scope binding")}
			}
		}
		if tx.db.authoringScope != "" {
			expectedArgs = 4
			authoringMarker := "public.mcp_mentor_authoring_permission"
			action, marker = tx.db.authoringAction, authoringMarker
			if len(args) != expectedArgs || args[3] != tx.db.authoringScope || !strings.Contains(query, "marker.scope=$4") {
				return mentorStoreRow{err: errors.New("missing exact authoring scope binding")}
			}
		}
		if tx.db.managementScope != "" {
			expectedArgs = 4
			action = "mcp.mentor.offers.publish"
			marker = "public.mcp_mentor_management_permission"
			if len(args) != expectedArgs || args[3] != tx.db.managementScope || !strings.Contains(query, "marker.scope=$4") {
				return mentorStoreRow{err: errors.New("missing exact management scope binding")}
			}
		}
		if tx.db.finalScope != "" {
			expectedArgs = 4
			action = tx.db.finalAction
			marker = "public.mcp_mentor_skill_final_review_permission"
			if len(args) != expectedArgs || args[3] != tx.db.finalScope || !strings.Contains(query, "marker.scope=$4") {
				return mentorStoreRow{err: errors.New("missing exact sensitive scope binding")}
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

func TestMCPMentorAuthoringPermissionUsesAnExactScopeMarker(t *testing.T) {
	command := mentorStoreProof("APPROVE", 2).Command
	for scope, action := range map[string]string{
		"mentor:courses:write":   "mcp.mentor.courses.write",
		"mentor:tasks:write":     "mcp.mentor.tasks.write",
		"mentor:courses:publish": "mcp.mentor.courses.publish",
		"mentor:tasks:publish":   "mcp.mentor.tasks.publish",
	} {
		t.Run(scope, func(t *testing.T) {
			for _, assigned := range []bool{false, true} {
				base := newMentorReadbackDBFixture()
				base.current(command)
				db := &mcpMentorReadDB{base: base, authoringScope: scope, authoringAction: action, permission: assigned}
				result, err := NewMCPMentorAccessReader(db).ReadMCPMentorAccess(context.Background(), command.TargetUserID, scope)
				if err != nil || !result.Active || result.Allowed != assigned || db.permissionReads != 1 || base.commitCount != 1 {
					t.Fatalf("authoring permission did not require exact marker: %+v %v", result, err)
				}
			}
		})
	}
}

func TestMCPMentorManagementPermissionUsesExactMarkerScope(t *testing.T) {
	command := mentorStoreProof("APPROVE", 2).Command
	for _, assigned := range []bool{false, true} {
		base := newMentorReadbackDBFixture()
		base.current(command)
		scope := "mentor:offers:publish"
		db := &mcpMentorReadDB{base: base, managementScope: scope, permission: assigned}
		result, err := NewMCPMentorAccessReader(db).ReadMCPMentorAccess(context.Background(), command.TargetUserID, scope)
		if err != nil || !result.Active || result.Allowed != assigned || db.permissionReads != 1 || base.commitCount != 1 {
			t.Fatalf("management scope changed explicit permission: %+v %v", result, err)
		}
	}
}

func TestMCPMentorFinalSkillAndReviewEachRequireTheirExactPermission(t *testing.T) {
	command := mentorStoreProof("APPROVE", 2).Command
	for scope, action := range map[string]string{
		"mentor:skills:publish": "mcp.mentor.skills.publish",
		"mentor:reviews:write":  "mcp.mentor.reviews.write",
		"mentor:reviews:decide": "mcp.mentor.reviews.decide",
	} {
		for _, assigned := range []bool{false, true} {
			base := newMentorReadbackDBFixture()
			base.current(command)
			db := &mcpMentorReadDB{base: base, finalScope: scope, finalAction: action, permission: assigned}
			result, err := NewMCPMentorAccessReader(db).ReadMCPMentorAccess(context.Background(), command.TargetUserID, scope)
			if err != nil || !result.Active || result.Allowed != assigned || db.permissionReads != 1 || base.commitCount != 1 {
				t.Fatalf("scope %s bypassed own marker binding: %+v %v", scope, result, err)
			}
		}
	}
}

func TestMCPMentorCohortResponseNeedsExactPermission(t *testing.T) {
	command := mentorStoreProof("APPROVE", 2).Command
	for _, assigned := range []bool{false, true} {
		base := newMentorReadbackDBFixture()
		base.current(command)
		db := &mcpMentorReadDB{base: base, cohortRespond: true, permission: assigned}
		result, err := NewMCPMentorAccessReader(db).ReadMCPMentorAccess(context.Background(), command.TargetUserID, domain.MCPMentorCohortRespondScope)
		if err != nil || !result.Active || result.Allowed != assigned || db.permissionReads != 1 || base.commitCount != 1 {
			t.Fatalf("cohort response did not use its exact permission: %+v %v", result, err)
		}
	}
}

func TestMCPMentorStudentFeedbackNeedsExactPermission(t *testing.T) {
	command := mentorStoreProof("APPROVE", 2).Command
	for _, assigned := range []bool{false, true} {
		base := newMentorReadbackDBFixture()
		base.current(command)
		db := &mcpMentorReadDB{base: base, studentFeedback: true, permission: assigned}
		result, err := NewMCPMentorAccessReader(db).ReadMCPMentorAccess(context.Background(), command.TargetUserID, domain.MCPMentorStudentFeedbackScope)
		if err != nil || !result.Active || result.Allowed != assigned || db.permissionReads != 1 || base.commitCount != 1 {
			t.Fatalf("student feedback did not use its exact permission: %+v %v", result, err)
		}
	}
}

func TestMCPMentorDialogWriteNeedsExactPermission(t *testing.T) {
	command := mentorStoreProof("APPROVE", 2).Command
	for _, assigned := range []bool{false, true} {
		base := newMentorReadbackDBFixture()
		base.current(command)
		db := &mcpMentorReadDB{base: base, dialogWrite: true, permission: assigned}
		result, err := NewMCPMentorAccessReader(db).ReadMCPMentorAccess(context.Background(), command.TargetUserID, domain.MCPMentorDialogWriteScope)
		if err != nil || !result.Active || result.Allowed != assigned || db.permissionReads != 1 || base.commitCount != 1 {
			t.Fatalf("dialog write did not use its exact permission: %+v %v", result, err)
		}
	}
}

func TestMCPMentorTaskAssignmentUsesExactPermission(t *testing.T) {
	command := mentorStoreProof("APPROVE", 2).Command
	for _, scope := range []string{"mentor:students:assign", "mentor:cohorts:assign"} {
		base := newMentorReadbackDBFixture()
		base.current(command)
		for _, assigned := range []bool{false, true} {
			db := &mcpMentorReadDB{base: base, taskAssignmentScope: scope, permission: assigned}
			result, err := NewMCPMentorAccessReader(db).ReadMCPMentorAccess(context.Background(), command.TargetUserID, scope)
			if err != nil || !result.Active || result.Allowed != assigned || db.permissionReads != 1 {
				t.Fatalf("task assignment scope %s did not use its exact permission: %+v %v", scope, result, err)
			}
		}
	}
}
