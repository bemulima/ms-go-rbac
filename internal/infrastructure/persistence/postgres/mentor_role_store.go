package repo

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/example/ms-rbac-service/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type mentorRoleStoreDB interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

// MentorRoleStore owns one serialized authority/receipt/fence/scoped-role
// transaction. It is not mounted by this source-only slice.
type MentorRoleStore struct{ db mentorRoleStoreDB }

func NewMentorRoleStore(db mentorRoleStoreDB) *MentorRoleStore { return &MentorRoleStore{db: db} }

func (store *MentorRoleStore) ApplyMentorRole(ctx context.Context, admitted domain.MentorRoleProof, revalidate domain.MentorRoleProofRevalidator) (domain.MentorRolePlan, error) {
	if store == nil || mentorStoreNil(store.db) {
		return domain.MentorRolePlan{}, domain.ErrAuthorityUnavailable
	}
	if ctx == nil || ctx.Err() != nil || revalidate == nil || !domain.ValidMentorRoleProofShape(admitted) {
		return domain.MentorRolePlan{}, domain.ErrUnauthenticated
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := recheckMentorStoreProof(ctx, admitted, revalidate); err != nil {
		return domain.MentorRolePlan{}, err
	}
	tx, err := store.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadWrite})
	if err != nil || mentorStoreNil(tx) {
		return domain.MentorRolePlan{}, domain.ErrAuthorityUnavailable
	}
	committed := false
	defer func() {
		if !committed {
			// Cancellation must not abandon an open transaction. Cleanup is
			// separately bounded and never starts another mutation or retry.
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
			defer stop()
			_ = tx.Rollback(cleanup)
		}
	}()
	// Qualify owned SQL and pin the transaction's search path.
	// pg_temp must be explicit and last: omitting it searches temporary tables
	// first, allowing a connection-local lookalike to evade our public locks.
	// Table exclusion, not advisory locks, also serializes existing writers.
	for _, query := range []string{
		`SELECT pg_catalog.set_config('lock_timeout', '2s', true), pg_catalog.set_config('statement_timeout', '4s', true), pg_catalog.set_config('search_path', 'pg_catalog,public,pg_temp', true)`,
		`LOCK TABLE public.role, public.service, public.service_role, public.mentor_role_scope IN SHARE MODE`,
		`LOCK TABLE public.principal_role, public.mentor_role_command_receipt, public.mentor_role_fence IN SHARE ROW EXCLUSIVE MODE`,
	} {
		if _, err := tx.Exec(ctx, query); err != nil {
			return domain.MentorRolePlan{}, domain.ErrAuthorityUnavailable
		}
	}
	if err := recheckMentorStoreProof(ctx, admitted, revalidate); err != nil {
		return domain.MentorRolePlan{}, err
	}
	scope, err := readMentorStoreScope(ctx, tx)
	if err != nil {
		return domain.MentorRolePlan{}, err
	}
	// This plain SELECT runs on this locked transaction, never through Get's
	// legacy any-scope fallback or a second pool connection. FOR UPDATE here
	// would introduce a cycle with existing row-lock-then-write operators.
	if err := checkMentorCanonicalAdmin(ctx, tx, admitted.Command.AdminID); err != nil {
		return domain.MentorRolePlan{}, err
	}
	snapshot, err := readMentorStoreSnapshot(ctx, tx, admitted.Command, scope)
	if err != nil {
		return domain.MentorRolePlan{}, err
	}
	plan, err := domain.PlanMentorRoleCommand(admitted.Command, snapshot)
	if err != nil {
		return domain.MentorRolePlan{}, err
	}
	if err := checkMentorPhysicalAssignment(ctx, tx, admitted.Command.TargetUserID, scope, snapshot.ApplicationFence); err != nil {
		return domain.MentorRolePlan{}, err
	}
	if plan.Write {
		if err := writeMentorStorePlan(ctx, tx, plan, snapshot.ApplicationFence, scope); err != nil {
			return domain.MentorRolePlan{}, err
		}
	}
	// Replays have no data writes but require the same fresh proof/current
	// Admin/current physical-state guarantees as a new mutation.
	if err := recheckMentorStoreProof(ctx, admitted, revalidate); err != nil {
		return domain.MentorRolePlan{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		// The server may have committed before an ACK was lost. Return no plan;
		// a fresh authenticated retry resolves the immutable command receipt.
		return domain.MentorRolePlan{}, domain.ErrAuthorityUnavailable
	}
	committed = true
	return plan, nil
}

type mentorStoreScope struct{ roleID, serviceID string }

func checkMentorCanonicalAdmin(ctx context.Context, tx pgx.Tx, adminID string) error {
	var roleKey string
	var count int64
	err := tx.QueryRow(ctx, `SELECT COALESCE(MIN(r.key), ''), COUNT(*)
		FROM public.principal_role pr JOIN public.role r ON r.id=pr.role_id
		WHERE pr.principal_id=$1 AND pr.principal_kind=$2 AND pr.tenant_id=$3
			AND pr.service_id=$4 AND pr.resource_kind=$5 AND pr.resource_id=$6`,
		adminID, string(defaultRoleKind), defaultTenantID, defaultServiceID, defaultScopeKind, defaultResourceID).Scan(&roleKey, &count)
	if err != nil || count < 0 || count > 1 {
		return domain.ErrAuthorityUnavailable
	}
	if count != 1 || roleKey != "admin" {
		return domain.ErrMentorRoleForbidden
	}
	return nil
}

func readMentorStoreScope(ctx context.Context, tx pgx.Tx) (mentorStoreScope, error) {
	var scope mentorStoreScope
	var total, valid int64
	err := tx.QueryRow(ctx, `SELECT COUNT(*),
		COUNT(*) FILTER (WHERE marker.singleton AND r.key='mentor' AND r.title='Mentor'
			AND s.key='ms-go-mentor' AND s.title='Mentor Service'
			AND sr.role_id=marker.role_id AND sr.service_id=marker.service_id),
		COALESCE(MIN(marker.role_id::text), ''), COALESCE(MIN(marker.service_id::text), '')
		FROM public.mentor_role_scope marker
		LEFT JOIN public.role r ON r.id=marker.role_id
		LEFT JOIN public.service s ON s.id=marker.service_id
		LEFT JOIN public.service_role sr ON sr.role_id=marker.role_id AND sr.service_id=marker.service_id`).
		Scan(&total, &valid, &scope.roleID, &scope.serviceID)
	if err != nil || total != 1 || valid != 1 || !mentorStoreUUID(scope.roleID) || !mentorStoreUUID(scope.serviceID) || scope.serviceID == defaultServiceID {
		return mentorStoreScope{}, domain.ErrAuthorityUnavailable
	}
	return scope, nil
}

type mentorStoreRecord struct {
	command           domain.MentorRoleCommand
	roleID, serviceID string
}

func (r mentorStoreRecord) fence() domain.MentorRoleFence {
	return domain.MentorRoleFence{Command: r.command, Active: r.command.Decision == domain.MentorRoleDecisionApprove, Suspended: r.command.Decision == domain.MentorRoleDecisionSuspend}
}

func readMentorStoreRecord(row pgx.Row, scope mentorStoreScope, fence bool) (*mentorStoreRecord, error) {
	if mentorStoreNil(row) {
		return nil, domain.ErrAuthorityUnavailable
	}
	var r mentorStoreRecord
	var revision int64
	present := true
	dest := []any{&r.command.Issuer, &r.command.RequestID, &r.command.AdminID, &r.command.TargetUserID, &r.command.ApplicationID, &revision, &r.command.Decision, &r.command.DecisionDigest, &r.command.Role, &r.command.Service, &r.roleID, &r.serviceID}
	if fence {
		dest = append(dest, &present)
	}
	if err := row.Scan(dest...); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, domain.ErrAuthorityUnavailable
	}
	if !present || revision <= 0 {
		return nil, domain.ErrMentorRoleInvalidSnapshot
	}
	r.command.ApplicationRevision = uint64(revision)
	if !domain.ValidMentorRoleCommand(r.command) || r.roleID != scope.roleID || r.serviceID != scope.serviceID {
		return nil, domain.ErrMentorRoleInvalidSnapshot
	}
	return &r, nil
}

const mentorFenceSelect = `SELECT f.issuer, f.request_id::text, COALESCE(r.admin_id::text, ''),
	f.target_user_id::text, f.application_id::text, f.application_revision,
	COALESCE(r.decision, ''), COALESCE(r.decision_digest, ''), f.role_key, f.service_key,
	f.role_id::text, f.service_id::text, (r.request_id IS NOT NULL)
	FROM public.mentor_role_fence f
	LEFT JOIN public.mentor_role_command_receipt r ON r.issuer=f.issuer AND r.request_id=f.request_id
		AND r.application_id=f.application_id AND r.target_user_id=f.target_user_id
		AND r.role_key=f.role_key AND r.service_key=f.service_key AND r.role_id=f.role_id
		AND r.service_id=f.service_id AND r.application_revision=f.application_revision `

func readMentorStoreSnapshot(ctx context.Context, tx pgx.Tx, command domain.MentorRoleCommand, scope mentorStoreScope) (domain.MentorRoleSnapshot, error) {
	var snapshot domain.MentorRoleSnapshot
	r, err := readMentorStoreRecord(tx.QueryRow(ctx, `SELECT issuer, request_id::text, admin_id::text,
		target_user_id::text, application_id::text, application_revision, decision, decision_digest,
		role_key, service_key, role_id::text, service_id::text
		FROM public.mentor_role_command_receipt WHERE issuer=$1 AND request_id=$2`, command.Issuer, command.RequestID), scope, false)
	if err != nil {
		return domain.MentorRoleSnapshot{}, err
	}
	if r != nil {
		snapshot.Receipt = &domain.MentorRoleCommandReceipt{Command: r.command, Applied: r.fence()}
	}
	r, err = readMentorStoreRecord(tx.QueryRow(ctx, mentorFenceSelect+`WHERE f.application_id=$1`, command.ApplicationID), scope, true)
	if err != nil {
		return domain.MentorRoleSnapshot{}, err
	}
	if r != nil {
		f := r.fence()
		snapshot.ApplicationFence = &f
	}
	r, err = readMentorStoreRecord(tx.QueryRow(ctx, mentorFenceSelect+`WHERE f.target_user_id=$1 AND f.role_key=$2 AND f.service_key=$3`, command.TargetUserID, command.Role, command.Service), scope, true)
	if err != nil {
		return domain.MentorRoleSnapshot{}, err
	}
	if r != nil {
		f := r.fence()
		snapshot.TargetFence = &f
	}
	return snapshot, nil
}

func checkMentorPhysicalAssignment(ctx context.Context, tx pgx.Tx, target string, scope mentorStoreScope, current *domain.MentorRoleFence) error {
	var total, mentor int64
	err := tx.QueryRow(ctx, `SELECT COUNT(*), COUNT(*) FILTER (WHERE role_id=$7)
		FROM public.principal_role WHERE principal_id=$1 AND principal_kind=$2 AND tenant_id=$3
			AND service_id=$4 AND resource_kind=$5 AND resource_id=$6`, target, string(defaultRoleKind), defaultTenantID, scope.serviceID, defaultScopeKind, defaultResourceID, scope.roleID).Scan(&total, &mentor)
	if err != nil {
		return domain.ErrAuthorityUnavailable
	}
	if current == nil {
		if total != 0 || mentor != 0 {
			return domain.ErrMentorRoleConflict
		}
		return nil
	}
	expected := int64(0)
	if current.Active {
		expected = 1
	}
	if total != expected || mentor != expected {
		return domain.ErrMentorRoleInvalidSnapshot
	}
	return nil
}

func writeMentorStorePlan(ctx context.Context, tx pgx.Tx, plan domain.MentorRolePlan, previous *domain.MentorRoleFence, scope mentorStoreScope) error {
	c := plan.Receipt.Command
	tag, err := tx.Exec(ctx, `INSERT INTO public.mentor_role_command_receipt
		(issuer, request_id, admin_id, target_user_id, application_id, application_revision,
		decision, decision_digest, role_key, service_key, role_id, service_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, c.Issuer, c.RequestID, c.AdminID, c.TargetUserID, c.ApplicationID, int64(c.ApplicationRevision), c.Decision, c.DecisionDigest, c.Role, c.Service, scope.roleID, scope.serviceID)
	if err := mentorStoreWriteResult(tag, err, 1); err != nil {
		return err
	}
	args := []any{c.TargetUserID, string(defaultRoleKind), scope.roleID, defaultTenantID, scope.serviceID, defaultScopeKind, defaultResourceID}
	expected := int64(1)
	if c.Decision == domain.MentorRoleDecisionApprove {
		tag, err = tx.Exec(ctx, `INSERT INTO public.principal_role
			(principal_id, principal_kind, role_id, tenant_id, service_id, resource_kind, resource_id)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`, args...)
	} else {
		tag, err = tx.Exec(ctx, `DELETE FROM public.principal_role
			WHERE principal_id=$1 AND principal_kind=$2 AND role_id=$3 AND tenant_id=$4
				AND service_id=$5 AND resource_kind=$6 AND resource_id=$7`, args...)
		if previous == nil || !previous.Active {
			expected = 0
		}
	}
	if err := mentorStoreWriteResult(tag, err, expected); err != nil {
		return err
	}
	if previous == nil {
		tag, err = tx.Exec(ctx, `INSERT INTO public.mentor_role_fence
			(application_id, issuer, target_user_id, role_key, service_key, role_id, service_id, application_revision, request_id)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, c.ApplicationID, c.Issuer, c.TargetUserID, c.Role, c.Service, scope.roleID, scope.serviceID, int64(c.ApplicationRevision), c.RequestID)
	} else {
		tag, err = tx.Exec(ctx, `UPDATE public.mentor_role_fence SET issuer=$1, application_revision=$2, request_id=$3
			WHERE application_id=$4 AND issuer=$5 AND application_revision=$6 AND request_id=$7`, c.Issuer, int64(c.ApplicationRevision), c.RequestID, c.ApplicationID, previous.Command.Issuer, int64(previous.Command.ApplicationRevision), previous.Command.RequestID)
	}
	return mentorStoreWriteResult(tag, err, 1)
}

func recheckMentorStoreProof(ctx context.Context, admitted domain.MentorRoleProof, check domain.MentorRoleProofRevalidator) error {
	if ctx.Err() != nil {
		return domain.ErrUnauthenticated
	}
	current, err := check(ctx)
	if err != nil {
		if errors.Is(err, domain.ErrUnauthenticated) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return domain.ErrUnauthenticated
		}
		return domain.ErrAuthorityUnavailable
	}
	if ctx.Err() != nil || current != admitted || !domain.ValidMentorRoleProofShape(current) {
		return domain.ErrUnauthenticated
	}
	return nil
}

func mentorStoreWriteResult(tag pgconn.CommandTag, err error, expected int64) error {
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return domain.ErrMentorRoleConflict
		}
		return domain.ErrAuthorityUnavailable
	}
	if tag.RowsAffected() != expected {
		return domain.ErrMentorRoleInvalidSnapshot
	}
	return nil
}

func mentorStoreUUID(value string) bool {
	return domain.ValidPrincipalID(value) && value == strings.ToLower(value)
}

func mentorStoreNil(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

var _ domain.MentorRoleMutationStore = (*MentorRoleStore)(nil)
