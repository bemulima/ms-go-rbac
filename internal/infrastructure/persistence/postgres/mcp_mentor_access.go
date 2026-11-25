package repo

import (
	"context"
	"time"

	"github.com/example/ms-rbac-service/internal/domain"
	"github.com/jackc/pgx/v5"
)

// MCPMentorAccessReader uses the same owner marker, immutable receipt, bilateral
// fence and physical-assignment checks as Mentor's signed role readback. The
// explicit requested permission is read in that SAME read-only snapshot.
type MCPMentorAccessReader struct{ db mentorRoleStoreDB }

func NewMCPMentorAccessReader(db mentorRoleStoreDB) *MCPMentorAccessReader {
	return &MCPMentorAccessReader{db: db}
}

func (r *MCPMentorAccessReader) ReadMCPMentorAccess(ctx context.Context, subject, requestedScope string) (domain.MCPMentorAccess, error) {
	denied := domain.MCPMentorAccess{}
	if r == nil || mentorStoreNil(r.db) || ctx == nil || ctx.Err() != nil || !mentorStoreUUID(subject) || !domain.ValidMCPMentorScope(requestedScope) {
		return denied, domain.ErrAuthorityUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil || mentorStoreNil(tx) {
		return denied, domain.ErrAuthorityUnavailable
	}
	committed := false
	defer func() {
		if !committed {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
			defer stop()
			_ = tx.Rollback(cleanup)
		}
	}()
	if _, err = tx.Exec(ctx, `SELECT pg_catalog.set_config('lock_timeout', '2s', true), pg_catalog.set_config('statement_timeout', '4s', true), pg_catalog.set_config('search_path', 'pg_catalog,public,pg_temp', true)`); err != nil {
		return denied, domain.ErrAuthorityUnavailable
	}
	readTx := mentorReadbackStrictTx{Tx: tx}
	scope, err := readMentorStoreScope(ctx, readTx)
	if err != nil {
		return denied, domain.ErrAuthorityUnavailable
	}
	current, err := readMentorStoreRecord(readTx.QueryRow(ctx, mentorFenceSelect+`WHERE f.target_user_id=$1 AND f.role_key=$2 AND f.service_key=$3`, subject, domain.MentorRole, domain.MentorRoleService), scope, true)
	if err != nil {
		return denied, domain.ErrAuthorityUnavailable
	}
	result := denied
	if current == nil {
		if err = checkMentorPhysicalAssignment(ctx, readTx, subject, scope, nil); err != nil {
			return denied, domain.ErrAuthorityUnavailable
		}
	} else {
		if current.command.TargetUserID != subject {
			return denied, domain.ErrAuthorityUnavailable
		}
		snapshot, err := readMentorStoreSnapshot(ctx, readTx, current.command, scope)
		if err != nil || !validMentorReadbackOwnedHistory(current.command, snapshot) || snapshot.TargetFence.Command != current.command {
			return denied, domain.ErrAuthorityUnavailable
		}
		if err = checkMentorPhysicalAssignment(ctx, readTx, subject, scope, snapshot.TargetFence); err != nil {
			return denied, domain.ErrAuthorityUnavailable
		}
		result.Active = current.command.Decision == domain.MentorRoleDecisionApprove
		if result.Active {
			// The permission must be attached to this exact marker-owned Mentor
			// role. A similarly named permission, scoped override or Admin role
			// cannot authorize MCP. This migration creates no default grants.
			action := domain.MCPMentorProfilePermission
			marker := "public.mcp_mentor_profile_permission"
			if requestedScope == domain.MCPMentorOffersScope {
				action = domain.MCPMentorOffersPermission
				marker = "public.mcp_mentor_offers_permission"
			} else if requestedScope == domain.MCPMentorSkillDraftScope {
				action = domain.MCPMentorSkillDraftPermission
				marker = "public.mcp_mentor_skill_draft_permission"
			} else if requestedScope == domain.MCPMentorCohortRespondScope {
				action = domain.MCPMentorCohortRespondAction
				marker = "public.mcp_mentor_cohort_response_permission"
			} else if requestedScope == domain.MCPMentorStudentFeedbackScope {
				action = domain.MCPMentorStudentFeedbackAction
				marker = "public.mcp_mentor_student_feedback_permission"
			}
			workspaceAction := domain.MCPMentorWorkspaceReadAction(requestedScope)
			scopeMarker := "public.mcp_mentor_workspace_read_permission"
			if authoringAction := domain.MCPMentorAuthoringAction(requestedScope); authoringAction != "" {
				workspaceAction, scopeMarker = authoringAction, "public.mcp_mentor_authoring_permission"
			}
			if finalAction := domain.MCPMentorSkillFinalReviewAction(requestedScope); finalAction != "" {
				workspaceAction, scopeMarker = finalAction, "public.mcp_mentor_skill_final_review_permission"
			}
			if workspaceAction != "" {
				err = readTx.QueryRow(ctx, `SELECT EXISTS (
					SELECT 1 FROM public.role_permission rp JOIN public.permission p ON p.id=rp.permission_id
					JOIN `+scopeMarker+` marker ON marker.permission_id=p.id AND marker.scope=$4
					WHERE rp.role_id=$1 AND rp.resource_id=$2 AND p.action=$3 AND p.resource_kind=''
				)`, scope.roleID, defaultResourceID, workspaceAction, requestedScope).Scan(&result.Allowed)
			} else if managementAction := domain.MCPMentorManagementAction(requestedScope); managementAction != "" {
				err = readTx.QueryRow(ctx, `SELECT EXISTS (
					SELECT 1 FROM public.role_permission rp JOIN public.permission p ON p.id=rp.permission_id
					JOIN public.mcp_mentor_management_permission marker ON marker.permission_id=p.id AND marker.scope=$4
					WHERE rp.role_id=$1 AND rp.resource_id=$2 AND p.action=$3 AND p.resource_kind=''
				)`, scope.roleID, defaultResourceID, managementAction, requestedScope).Scan(&result.Allowed)
			} else {
				err = readTx.QueryRow(ctx, `SELECT EXISTS (
					SELECT 1 FROM public.role_permission rp JOIN public.permission p ON p.id=rp.permission_id JOIN `+marker+` marker ON marker.permission_id=p.id AND marker.singleton
					WHERE rp.role_id=$1 AND rp.resource_id=$2 AND p.action=$3 AND p.resource_kind=''
				)`, scope.roleID, defaultResourceID, action).Scan(&result.Allowed)
			}
			if err != nil {
				return denied, domain.ErrAuthorityUnavailable
			}
		}
	}
	if ctx.Err() != nil || tx.Commit(ctx) != nil {
		return denied, domain.ErrAuthorityUnavailable
	}
	committed = true
	if ctx.Err() != nil {
		return denied, domain.ErrAuthorityUnavailable
	}
	return result, nil
}
