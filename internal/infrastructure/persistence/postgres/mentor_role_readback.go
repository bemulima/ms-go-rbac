package repo

import (
	"context"
	"time"

	"github.com/example/ms-rbac-service/internal/domain"
	"github.com/jackc/pgx/v5"
)

// MentorRoleReader observes one coherent snapshot. It neither mutates roles
// nor rechecks the historical granting Admin's present privileges.
type MentorRoleReader struct{ db mentorRoleStoreDB }

func NewMentorRoleReader(db mentorRoleStoreDB) *MentorRoleReader { return &MentorRoleReader{db: db} }

func (reader *MentorRoleReader) ReadMentorRole(ctx context.Context, command domain.MentorRoleCommand) (domain.MentorRoleReadbackResult, error) {
	if reader == nil || mentorStoreNil(reader.db) || ctx == nil || ctx.Err() != nil || !domain.ValidMentorRoleCommand(command) {
		return domain.MentorRoleReadbackResult{}, domain.ErrAuthorityUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := reader.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil || mentorStoreNil(tx) {
		return domain.MentorRoleReadbackResult{}, domain.ErrAuthorityUnavailable
	}
	committed := false
	defer func() {
		if !committed {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
			defer stop()
			_ = tx.Rollback(cleanup)
		}
	}()
	if _, err := tx.Exec(ctx, `SELECT pg_catalog.set_config('lock_timeout', '2s', true), pg_catalog.set_config('statement_timeout', '4s', true), pg_catalog.set_config('search_path', 'pg_catalog,public,pg_temp', true)`); err != nil || ctx.Err() != nil {
		return domain.MentorRoleReadbackResult{}, domain.ErrAuthorityUnavailable
	}
	// Reuse the mutation owner's exact metadata/receipt/fence/physical SQL,
	// without its locks, Admin query, planner, writes or READ COMMITTED boundary.
	// Strict absence admission prevents a joined/wrapped driver failure from
	// becoming a signed semantic DENY through errors.Is(ErrNoRows).
	readTx := mentorReadbackStrictTx{Tx: tx}
	scope, err := readMentorStoreScope(ctx, readTx)
	if err != nil || ctx.Err() != nil {
		return domain.MentorRoleReadbackResult{}, domain.ErrAuthorityUnavailable
	}
	snapshot, err := readMentorStoreSnapshot(ctx, readTx, command, scope)
	if err != nil || ctx.Err() != nil || !validMentorReadbackQueryPins(command, snapshot) {
		return domain.MentorRoleReadbackResult{}, domain.ErrAuthorityUnavailable
	}
	// A valid but mismatching request may name an application and target that
	// belong to two different current commands. Validate those observed facts
	// through their own bilateral indexes before returning only UNCONFIRMED.
	cache := map[domain.MentorRoleCommand]domain.MentorRoleSnapshot{command: snapshot}
	checked := make(map[domain.MentorRoleCommand]bool)
	validateRelated := func(actual domain.MentorRoleCommand) error {
		if checked[actual] {
			return nil
		}
		owned, ok := cache[actual]
		if !ok {
			var err error
			owned, err = readMentorStoreSnapshot(ctx, readTx, actual, scope)
			if err != nil {
				return domain.ErrAuthorityUnavailable
			}
			cache[actual] = owned
		}
		if ctx.Err() != nil || !validMentorReadbackOwnedHistory(actual, owned) {
			return domain.ErrAuthorityUnavailable
		}
		if err := checkMentorPhysicalAssignment(ctx, readTx, actual.TargetUserID, scope, owned.TargetFence); err != nil || ctx.Err() != nil {
			return domain.ErrAuthorityUnavailable
		}
		checked[actual] = true
		return nil
	}
	for _, fence := range []*domain.MentorRoleFence{snapshot.ApplicationFence, snapshot.TargetFence} {
		if fence != nil {
			if err := validateRelated(fence.Command); err != nil {
				return domain.MentorRoleReadbackResult{}, domain.ErrAuthorityUnavailable
			}
		}
	}
	if snapshot.Receipt != nil {
		if err := validateRelated(snapshot.Receipt.Command); err != nil {
			return domain.MentorRoleReadbackResult{}, domain.ErrAuthorityUnavailable
		}
	}
	if snapshot.TargetFence == nil {
		if err := checkMentorPhysicalAssignment(ctx, readTx, command.TargetUserID, scope, nil); err != nil || ctx.Err() != nil {
			return domain.MentorRoleReadbackResult{}, domain.ErrAuthorityUnavailable
		}
	}
	result := domain.MentorRoleReadbackResult{}
	if snapshot.Receipt != nil && snapshot.Receipt.Command == command && snapshot.ApplicationFence != nil &&
		snapshot.TargetFence != nil && snapshot.ApplicationFence.Command == command && snapshot.TargetFence.Command == command {
		result = domain.MentorRoleReadbackResult{Confirmed: true, Active: command.Decision == domain.MentorRoleDecisionApprove}
	}
	if ctx.Err() != nil || !domain.ValidMentorRoleReadbackResult(command, result) {
		return domain.MentorRoleReadbackResult{}, domain.ErrAuthorityUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.MentorRoleReadbackResult{}, domain.ErrAuthorityUnavailable
	}
	committed = true
	// This is read-only: cancellation after Commit does not undo a mutation or
	// assert rollback. It simply withholds a now-unusable observation.
	if ctx.Err() != nil {
		return domain.MentorRoleReadbackResult{}, domain.ErrAuthorityUnavailable
	}
	return result, nil
}

func validMentorReadbackQueryPins(query domain.MentorRoleCommand, snapshot domain.MentorRoleSnapshot) bool {
	if r := snapshot.Receipt; r != nil {
		if r.Command.Issuer != query.Issuer || r.Command.RequestID != query.RequestID || !domain.ValidMentorRoleCommand(r.Command) || r.Applied.Command != r.Command ||
			r.Applied.Active != (r.Command.Decision == domain.MentorRoleDecisionApprove) || r.Applied.Suspended != (r.Command.Decision == domain.MentorRoleDecisionSuspend) {
			return false
		}
	}
	if a := snapshot.ApplicationFence; a != nil && a.Command.ApplicationID != query.ApplicationID {
		return false
	}
	if target := snapshot.TargetFence; target != nil && (target.Command.TargetUserID != query.TargetUserID || target.Command.Role != query.Role || target.Command.Service != query.Service) {
		return false
	}
	return true
}

func validMentorReadbackOwnedHistory(actual domain.MentorRoleCommand, snapshot domain.MentorRoleSnapshot) bool {
	if !validMentorReadbackQueryPins(actual, snapshot) || snapshot.Receipt == nil || snapshot.Receipt.Command != actual || snapshot.ApplicationFence == nil || snapshot.TargetFence == nil || *snapshot.ApplicationFence != *snapshot.TargetFence {
		return false
	}
	current := snapshot.ApplicationFence.Command
	if !domain.ValidMentorRoleCommand(current) || current.Issuer != actual.Issuer || current.ApplicationID != actual.ApplicationID || current.TargetUserID != actual.TargetUserID || current.Role != actual.Role || current.Service != actual.Service || current.ApplicationRevision < actual.ApplicationRevision {
		return false
	}
	if current.ApplicationRevision == actual.ApplicationRevision {
		return current == actual
	}
	return actual.Decision == domain.MentorRoleDecisionApprove && current.Decision == domain.MentorRoleDecisionSuspend
}

type mentorReadbackStrictTx struct{ pgx.Tx }

func (tx mentorReadbackStrictTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return mentorReadbackStrictRow{row: tx.Tx.QueryRow(ctx, sql, args...)}
}

type mentorReadbackStrictRow struct{ row pgx.Row }

func (row mentorReadbackStrictRow) Scan(dest ...any) error {
	if mentorStoreNil(row.row) {
		return domain.ErrAuthorityUnavailable
	}
	err := row.row.Scan(dest...)
	if err == nil || err == pgx.ErrNoRows {
		return err
	}
	return domain.ErrAuthorityUnavailable
}

var _ domain.MentorRoleReadbackReader = (*MentorRoleReader)(nil)
