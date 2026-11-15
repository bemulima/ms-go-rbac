package repo

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/example/ms-rbac-service/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// This protocol fixture executes the actual reader but not PostgreSQL SQL.
// Its independent immutable snapshot changes only when a new read begins.
type mentorReadbackDBFixture struct {
	state                                  mentorStoreState
	events                                 []string
	failAt                                 string
	failErr                                error
	nilRowAt                               string
	options                                pgx.TxOptions
	beginCount, commitCount, rollbackCount int
	badProtocol                            bool
	onQuery                                func(string)
	onCommit                               func()
	beginCtx                               context.Context
}
type mentorReadbackTxFixture struct {
	pgx.Tx
	db               *mentorReadbackDBFixture
	snapshot         mentorStoreState
	settings, closed bool
}

func newMentorReadbackDBFixture() *mentorReadbackDBFixture {
	return &mentorReadbackDBFixture{state: newMentorStoreFixture().state.copy()}
}
func (db *mentorReadbackDBFixture) failure(kind string) error {
	db.events = append(db.events, kind)
	if db.failAt != kind {
		return nil
	}
	if db.failErr != nil {
		return db.failErr
	}
	return errors.New("private storage diagnostic")
}
func (db *mentorReadbackDBFixture) BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error) {
	db.beginCount++
	db.options = opts
	db.beginCtx = ctx
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 5*time.Second || opts.IsoLevel != pgx.RepeatableRead || opts.AccessMode != pgx.ReadOnly {
		db.badProtocol = true
		return nil, errors.New("reader lacks snapshot/read-only/bounds")
	}
	if err := db.failure("begin"); err != nil {
		return nil, err
	}
	return &mentorReadbackTxFixture{db: db, snapshot: db.state.copy()}, nil
}
func (tx *mentorReadbackTxFixture) Exec(ctx context.Context, q string, args ...any) (pgconn.CommandTag, error) {
	if err := tx.db.failure(mentorStoreQueryKind(q)); err != nil {
		return pgconn.CommandTag{}, err
	}
	if ctx.Err() != nil || tx.closed || len(args) != 0 || !strings.HasPrefix(q, "SELECT pg_catalog.set_config") || !strings.Contains(q, "'lock_timeout', '2s', true") || !strings.Contains(q, "'statement_timeout', '4s', true") || !strings.Contains(q, "'search_path', 'pg_catalog,public,pg_temp', true") {
		tx.db.badProtocol = true
		return pgconn.CommandTag{}, errors.New("unexpected mutation/lock/settings")
	}
	tx.settings = true
	return pgconn.NewCommandTag("SELECT 1"), nil
}
func (tx *mentorReadbackTxFixture) QueryRow(ctx context.Context, q string, args ...any) pgx.Row {
	kind := mentorStoreQueryKind(q)
	if tx.db.nilRowAt == kind {
		return nil
	}
	if err := tx.db.failure(kind); err != nil {
		return mentorStoreRow{err: err}
	}
	if ctx.Err() != nil || !tx.settings || tx.closed || strings.Contains(q, "FOR UPDATE") || strings.Contains(q, "FOR SHARE") || kind == "admin" {
		tx.db.badProtocol = true
		return mentorStoreRow{err: errors.New("unsafe read protocol")}
	}
	if tx.db.onQuery != nil {
		tx.db.onQuery(kind)
	}
	s := tx.snapshot
	switch kind {
	case "scope":
		return mentorStoreRow{values: []any{s.scopeCount, s.scopeValid, s.roleID, s.serviceID}}
	case "receipt":
		if len(args) != 2 || args[0] != domain.MentorRoleProofIssuer {
			return mentorStoreRow{err: errors.New("wrong receipt key")}
		}
		r, ok := s.receipts[args[1].(string)]
		if !ok {
			return mentorStoreRow{err: pgx.ErrNoRows}
		}
		return mentorStoreRow{values: mentorFixtureValues(r)}
	case "application_fence", "target_fence":
		if !strings.Contains(q, "LEFT JOIN public.mentor_role_command_receipt") {
			return mentorStoreRow{err: errors.New("lost dangling fence")}
		}
		var r mentorStoredFixture
		found := false
		if kind == "application_fence" {
			r, found = s.fences[args[0].(string)]
		} else {
			if len(args) != 3 || args[1] != domain.MentorRole || args[2] != domain.MentorRoleService {
				return mentorStoreRow{err: errors.New("wrong fence scope")}
			}
			for _, f := range s.fences {
				if f.command.TargetUserID == args[0] {
					r, found = f, true
					break
				}
			}
		}
		if !found {
			return mentorStoreRow{err: pgx.ErrNoRows}
		}
		receipt, exists := s.receipts[r.command.RequestID]
		present := exists && receipt == r
		values := mentorFixtureValues(r)
		if !present {
			values[2], values[6], values[7] = "", "", ""
		}
		return mentorStoreRow{values: append(values, present)}
	case "physical":
		if len(args) != 7 || args[1] != "user" || args[2] != defaultTenantID || args[3] != s.serviceID || args[4] != defaultScopeKind || args[5] != defaultResourceID || args[6] != s.roleID {
			return mentorStoreRow{err: errors.New("read escaped Mentor tuple")}
		}
		r := s.physical[args[0].(string)]
		return mentorStoreRow{values: []any{r.total, r.mentor}}
	default:
		tx.db.badProtocol = true
		return mentorStoreRow{err: errors.New("unexpected query")}
	}
}
func (tx *mentorReadbackTxFixture) Commit(ctx context.Context) error {
	if err := tx.db.failure("commit"); err != nil {
		return err
	}
	if ctx.Err() != nil || tx.closed || !tx.settings {
		return errors.New("invalid read commit")
	}
	tx.db.commitCount++
	tx.closed = true
	if tx.db.onCommit != nil {
		tx.db.onCommit()
	}
	return nil
}
func (tx *mentorReadbackTxFixture) Rollback(ctx context.Context) error {
	tx.db.rollbackCount++
	tx.db.events = append(tx.db.events, "rollback")
	deadline, ok := ctx.Deadline()
	if ctx.Err() != nil || !ok || time.Until(deadline) > time.Second {
		tx.db.badProtocol = true
	}
	tx.closed = true
	return nil
}
func (db *mentorReadbackDBFixture) current(c domain.MentorRoleCommand) {
	r := mentorStoredFixture{command: c, roleID: db.state.roleID, serviceID: db.state.serviceID}
	db.state.receipts[c.RequestID] = r
	db.state.fences[c.ApplicationID] = r
	if c.Decision == "APPROVE" {
		db.state.physical[c.TargetUserID] = mentorPhysicalFixture{1, 1}
	} else {
		delete(db.state.physical, c.TargetUserID)
	}
}
func assertMentorReadbackResult(t *testing.T, db *mentorReadbackDBFixture, c domain.MentorRoleCommand, want domain.MentorRoleReadbackResult) {
	t.Helper()
	before := db.state.copy()
	got, err := NewMentorRoleReader(db).ReadMentorRole(context.Background(), c)
	if err != nil || got != want || db.badProtocol {
		t.Fatalf("reader result=%v error=%v protocol=%v events=%v", got, err, db.badProtocol, db.events)
	}
	if !reflect.DeepEqual(before, db.state) {
		t.Fatal("read mutated persistent fixture state")
	}
}

func TestMentorRoleReadbackReaderCurrentApproveSuspendAndHistoricalDenial(t *testing.T) {
	db := newMentorReadbackDBFixture()
	approve := mentorStoreProof("APPROVE", 2).Command
	db.current(approve)
	assertMentorReadbackResult(t, db, approve, domain.MentorRoleReadbackResult{Confirmed: true, Active: true})
	db.state.admin = "student"
	db.state.adminCount = 0 // former Admin is not readback authority.
	assertMentorReadbackResult(t, db, approve, domain.MentorRoleReadbackResult{Confirmed: true, Active: true})
	suspend := mentorStoreProof("SUSPEND", 4).Command
	db.current(suspend)
	assertMentorReadbackResult(t, db, suspend, domain.MentorRoleReadbackResult{Confirmed: true, Active: false})
	assertMentorReadbackResult(t, db, approve, domain.MentorRoleReadbackResult{})
	if db.state.student != "student" || db.state.writes != 0 || db.commitCount != 4 || db.rollbackCount != 0 {
		t.Fatal("readback changed unrelated roles or failed transaction lifecycle")
	}
	for _, event := range db.events {
		if strings.Contains(event, "lock") || event == "admin" {
			t.Fatal("readback acquired mutation lock or rechecked old Admin")
		}
	}
}

func TestMentorRoleReadbackReaderRevokeFirstAndMissingCommand(t *testing.T) {
	db := newMentorReadbackDBFixture()
	approve := mentorStoreProof("APPROVE", 2).Command
	assertMentorReadbackResult(t, db, approve, domain.MentorRoleReadbackResult{})
	suspend := mentorStoreProof("SUSPEND", 3).Command
	db.current(suspend)
	assertMentorReadbackResult(t, db, suspend, domain.MentorRoleReadbackResult{Confirmed: true, Active: false})
	assertMentorReadbackResult(t, db, approve, domain.MentorRoleReadbackResult{})
}

func TestMentorRoleReadbackReaderCoherentMismatchesDoNotLeakCurrentState(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*domain.MentorRoleCommand)
	}{
		{"other target", func(c *domain.MentorRoleCommand) { c.TargetUserID = "00000000-0000-4000-8000-000000000b02" }},
		{"other application", func(c *domain.MentorRoleCommand) { c.ApplicationID = "00000000-0000-4000-8000-000000000c02" }},
		{"other actor", func(c *domain.MentorRoleCommand) { c.AdminID = "00000000-0000-4000-8000-000000000a02" }},
		{"other request", func(c *domain.MentorRoleCommand) { c.RequestID = "00000000-0000-4000-8000-000000000d03" }},
		{"suspend not applied", func(c *domain.MentorRoleCommand) { *c = mentorStoreProof("SUSPEND", 4).Command }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newMentorReadbackDBFixture()
			c := mentorStoreProof("APPROVE", 2).Command
			db.current(c)
			tc.edit(&c)
			c = mentorStoreDigest(c)
			assertMentorReadbackResult(t, db, c, domain.MentorRoleReadbackResult{})
		})
	}
}

func TestMentorRoleReadbackReaderCorruptSnapshotsFailUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*mentorReadbackDBFixture, domain.MentorRoleCommand)
	}{
		{"missing metadata", func(db *mentorReadbackDBFixture, _ domain.MentorRoleCommand) { db.state.scopeCount = 0 }},
		{"metadata drift", func(db *mentorReadbackDBFixture, _ domain.MentorRoleCommand) { db.state.scopeValid = 0 }},
		{"core service marker", func(db *mentorReadbackDBFixture, _ domain.MentorRoleCommand) { db.state.serviceID = defaultServiceID }},
		{"dangling fence receipt", func(db *mentorReadbackDBFixture, c domain.MentorRoleCommand) { delete(db.state.receipts, c.RequestID) }},
		{"orphan receipt", func(db *mentorReadbackDBFixture, c domain.MentorRoleCommand) {
			delete(db.state.fences, c.ApplicationID)
			delete(db.state.physical, c.TargetUserID)
		}},
		{"missing active assignment", func(db *mentorReadbackDBFixture, c domain.MentorRoleCommand) {
			delete(db.state.physical, c.TargetUserID)
		}},
		{"ambiguous assignments", func(db *mentorReadbackDBFixture, c domain.MentorRoleCommand) {
			db.state.physical[c.TargetUserID] = mentorPhysicalFixture{2, 1}
		}},
		{"wrong exact role", func(db *mentorReadbackDBFixture, c domain.MentorRoleCommand) {
			db.state.physical[c.TargetUserID] = mentorPhysicalFixture{1, 0}
		}},
		{"assignment without owner", func(db *mentorReadbackDBFixture, c domain.MentorRoleCommand) {
			delete(db.state.receipts, c.RequestID)
			delete(db.state.fences, c.ApplicationID)
		}},
		{"surviving revoked assignment", func(db *mentorReadbackDBFixture, c domain.MentorRoleCommand) {
			db.current(mentorStoreProof("SUSPEND", 4).Command)
			db.state.physical[c.TargetUserID] = mentorPhysicalFixture{1, 1}
		}},
		{"receipt digest corruption", func(db *mentorReadbackDBFixture, c domain.MentorRoleCommand) {
			r := db.state.receipts[c.RequestID]
			r.command.DecisionDigest = strings.Repeat("f", 64)
			db.state.receipts[c.RequestID] = r
		}},
		{"receipt metadata corruption", func(db *mentorReadbackDBFixture, c domain.MentorRoleCommand) {
			r := db.state.receipts[c.RequestID]
			r.roleID = "00000000-0000-4000-8000-000000000f03"
			db.state.receipts[c.RequestID] = r
		}},
		{"fence lookup corruption", func(db *mentorReadbackDBFixture, c domain.MentorRoleCommand) {
			r := db.state.fences[c.ApplicationID]
			r.command.ApplicationID = "00000000-0000-4000-8000-000000000c02"
			r.command = mentorStoreDigest(r.command)
			db.state.fences[c.ApplicationID] = r
			db.state.receipts[c.RequestID] = r
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newMentorReadbackDBFixture()
			c := mentorStoreProof("APPROVE", 2).Command
			db.current(c)
			tc.edit(db, c)
			before := db.state.copy()
			got, err := NewMentorRoleReader(db).ReadMentorRole(context.Background(), c)
			if err != domain.ErrAuthorityUnavailable || got != (domain.MentorRoleReadbackResult{}) {
				t.Fatalf("corruption became semantic response: result=%v error=%v", got, err)
			}
			if !reflect.DeepEqual(before, db.state) || db.commitCount != 0 || db.rollbackCount != 1 || db.badProtocol {
				t.Fatal("failed read changed state or leaked transaction")
			}
		})
	}
}

func TestMentorRoleReadbackReaderFailuresAreNotSemanticAbsence(t *testing.T) {
	for _, stage := range []string{"begin", "settings", "scope", "receipt", "application_fence", "target_fence", "physical", "commit"} {
		t.Run(stage, func(t *testing.T) {
			db := newMentorReadbackDBFixture()
			c := mentorStoreProof("APPROVE", 2).Command
			db.current(c)
			db.failAt = stage
			got, err := NewMentorRoleReader(db).ReadMentorRole(context.Background(), c)
			if err != domain.ErrAuthorityUnavailable || got != (domain.MentorRoleReadbackResult{}) || db.badProtocol {
				t.Fatalf("unsafe failure %v %v", got, err)
			}
			if stage != "begin" && db.rollbackCount != 1 {
				t.Fatal("read transaction not rolled back")
			}
		})
	}
	for _, stage := range []string{"receipt", "application_fence", "target_fence"} {
		t.Run("joined no rows "+stage, func(t *testing.T) {
			db := newMentorReadbackDBFixture()
			db.failAt = stage
			db.failErr = errors.Join(pgx.ErrNoRows, errors.New("private unknown failure"))
			got, err := NewMentorRoleReader(db).ReadMentorRole(context.Background(), mentorStoreProof("APPROVE", 2).Command)
			if err != domain.ErrAuthorityUnavailable || got != (domain.MentorRoleReadbackResult{}) || db.rollbackCount != 1 {
				t.Fatalf("unknown no-rows error signed away: %v", err)
			}
		})
	}
}

func TestMentorRoleReadbackReaderCoherentSnapshotAcrossConcurrentChange(t *testing.T) {
	db := newMentorReadbackDBFixture()
	approve := mentorStoreProof("APPROVE", 2).Command
	suspend := mentorStoreProof("SUSPEND", 4).Command
	db.current(approve)
	changed := false
	db.onQuery = func(kind string) {
		if kind == "scope" && !changed {
			changed = true
			db.current(suspend)
		}
	}
	got, err := NewMentorRoleReader(db).ReadMentorRole(context.Background(), approve)
	if err != nil || got != (domain.MentorRoleReadbackResult{Confirmed: true, Active: true}) || !changed {
		t.Fatalf("mixed snapshots: %v %v", got, err)
	}
	db.onQuery = nil
	assertMentorReadbackResult(t, db, approve, domain.MentorRoleReadbackResult{})
	assertMentorReadbackResult(t, db, suspend, domain.MentorRoleReadbackResult{Confirmed: true, Active: false})
	if db.state.fences[suspend.ApplicationID].command != suspend || db.state.physical[suspend.TargetUserID].total != 0 {
		t.Fatal("read commit restored old snapshot")
	}
}

func TestMentorRoleReadbackReaderDeniesMissingInvalidAndCancelledInputs(t *testing.T) {
	c := mentorStoreProof("APPROVE", 2).Command
	for _, tc := range []struct {
		name    string
		reader  *MentorRoleReader
		ctx     context.Context
		command domain.MentorRoleCommand
	}{
		{"nil reader", nil, context.Background(), c},
		{"nil db", NewMentorRoleReader(nil), context.Background(), c},
		{"typed nil db", NewMentorRoleReader((*mentorReadbackDBFixture)(nil)), context.Background(), c},
		{"nil context", NewMentorRoleReader(newMentorReadbackDBFixture()), nil, c},
		{"invalid command", NewMentorRoleReader(newMentorReadbackDBFixture()), context.Background(), domain.MentorRoleCommand{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.reader.ReadMentorRole(tc.ctx, tc.command)
			if err != domain.ErrAuthorityUnavailable || got != (domain.MentorRoleReadbackResult{}) {
				t.Fatalf("invalid input admitted: %v", err)
			}
		})
	}
	for _, stage := range []string{"before", "scope", "commit"} {
		t.Run("cancel "+stage, func(t *testing.T) {
			db := newMentorReadbackDBFixture()
			db.current(c)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if stage == "before" {
				cancel()
			} else if stage == "commit" {
				db.onCommit = cancel
			} else {
				db.onQuery = func(kind string) {
					if kind == stage {
						cancel()
					}
				}
			}
			got, err := NewMentorRoleReader(db).ReadMentorRole(ctx, c)
			if err != domain.ErrAuthorityUnavailable || got != (domain.MentorRoleReadbackResult{}) || db.badProtocol {
				t.Fatalf("cancellation exposed stale result: %v %v", got, err)
			}
			if stage == "before" && db.beginCount != 0 {
				t.Fatal("pre-cancelled call began transaction")
			}
			if stage == "scope" && db.rollbackCount != 1 {
				t.Fatal("cancelled read did not clean up")
			}
		})
	}
	t.Run("earlier deadline", func(t *testing.T) {
		db := newMentorReadbackDBFixture()
		db.current(c)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if _, err := NewMentorRoleReader(db).ReadMentorRole(ctx, c); err != nil {
			t.Fatal(err)
		}
		a, _ := ctx.Deadline()
		b, _ := db.beginCtx.Deadline()
		if !a.Equal(b) {
			t.Fatal("reader replaced earlier caller deadline")
		}
	})
}

type mentorReadbackBeginFixture func(context.Context, pgx.TxOptions) (pgx.Tx, error)

func (f mentorReadbackBeginFixture) BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error) {
	return f(ctx, opts)
}

func TestMentorRoleReadbackReaderRejectsNilTransactionAndRows(t *testing.T) {
	for _, tc := range []struct {
		name string
		tx   pgx.Tx
	}{
		{"nil transaction", nil},
		{"typed nil transaction", (*mentorReadbackTxFixture)(nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := mentorReadbackBeginFixture(func(context.Context, pgx.TxOptions) (pgx.Tx, error) { return tc.tx, nil })
			got, err := NewMentorRoleReader(db).ReadMentorRole(context.Background(), mentorStoreProof("APPROVE", 2).Command)
			if err != domain.ErrAuthorityUnavailable || got != (domain.MentorRoleReadbackResult{}) {
				t.Fatalf("nil transaction admitted: %v", err)
			}
		})
	}
	for _, stage := range []string{"scope", "receipt", "application_fence", "target_fence", "physical"} {
		t.Run("nil row "+stage, func(t *testing.T) {
			db := newMentorReadbackDBFixture()
			c := mentorStoreProof("APPROVE", 2).Command
			db.current(c)
			db.nilRowAt = stage
			got, err := NewMentorRoleReader(db).ReadMentorRole(context.Background(), c)
			if err != domain.ErrAuthorityUnavailable || got != (domain.MentorRoleReadbackResult{}) || db.rollbackCount != 1 {
				t.Fatalf("nil row became absence: %v", err)
			}
		})
	}
}

func TestMentorRoleReadbackReaderChecksBothForeignBindingsBeforeDeny(t *testing.T) {
	db := newMentorReadbackDBFixture()
	first := mentorStoreProof("APPROVE", 2).Command
	second := first
	second.TargetUserID = "00000000-0000-4000-8000-000000000b02"
	second.ApplicationID = "00000000-0000-4000-8000-000000000c02"
	second.RequestID = "00000000-0000-4000-8000-000000000d03"
	second = mentorStoreDigest(second)
	db.current(first)
	db.current(second)
	query := first
	query.TargetUserID = second.TargetUserID
	assertMentorReadbackResult(t, db, query, domain.MentorRoleReadbackResult{})
	delete(db.state.physical, first.TargetUserID)
	got, err := NewMentorRoleReader(db).ReadMentorRole(context.Background(), query)
	if err != domain.ErrAuthorityUnavailable || got != (domain.MentorRoleReadbackResult{}) {
		t.Fatalf("foreign observed corruption became DENY: %v", err)
	}
}

func TestMentorRoleReadbackReaderObservesActualMutationAdapterFacts(t *testing.T) {
	mutationDB := newMentorStoreFixture()
	approve := mentorStoreProof("APPROVE", 2)
	applyMentorFixture(t, mutationDB, approve)
	readDB := newMentorReadbackDBFixture()
	readDB.state = mutationDB.state.copy()
	assertMentorReadbackResult(t, readDB, approve.Command, domain.MentorRoleReadbackResult{Confirmed: true, Active: true})
	suspend := mentorStoreProof("SUSPEND", 4)
	applyMentorFixture(t, mutationDB, suspend)
	readDB.state = mutationDB.state.copy()
	assertMentorReadbackResult(t, readDB, suspend.Command, domain.MentorRoleReadbackResult{Confirmed: true, Active: false})
	assertMentorReadbackResult(t, readDB, approve.Command, domain.MentorRoleReadbackResult{})
	if readDB.state.student != "student" || readDB.state.writes != mutationDB.state.writes {
		t.Fatal("readback added writes or changed Student")
	}
}
