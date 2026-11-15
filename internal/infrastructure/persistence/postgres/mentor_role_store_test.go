package repo

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/example/ms-rbac-service/internal/domain"
	"github.com/example/ms-rbac-service/internal/infrastructure/client"
	"github.com/example/ms-rbac-service/internal/usecase"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const mentorStoreAdmin = "00000000-0000-4000-8000-000000000a01"
const mentorStoreTarget = "00000000-0000-4000-8000-000000000b01"
const mentorStoreApplication = "00000000-0000-4000-8000-000000000c01"
const mentorStoreRoleID = "00000000-0000-4000-8000-000000000f01"
const mentorStoreServiceID = "00000000-0000-4000-8000-000000000f02"

type mentorStoredFixture struct {
	command           domain.MentorRoleCommand
	roleID, serviceID string
}
type mentorPhysicalFixture struct{ total, mentor int64 }
type mentorStoreState struct {
	receipts               map[string]mentorStoredFixture
	fences                 map[string]mentorStoredFixture
	physical               map[string]mentorPhysicalFixture
	student                string
	admin                  string
	adminCount             int64
	scopeCount, scopeValid int64
	roleID, serviceID      string
	writes                 int
}

func (s mentorStoreState) copy() mentorStoreState {
	out := s
	out.receipts = map[string]mentorStoredFixture{}
	out.fences = map[string]mentorStoredFixture{}
	out.physical = map[string]mentorPhysicalFixture{}
	for k, v := range s.receipts {
		out.receipts[k] = v
	}
	for k, v := range s.fences {
		out.fences[k] = v
	}
	for k, v := range s.physical {
		out.physical[k] = v
	}
	return out
}

// Transaction protocol fixture only. It executes the production repository
// method; it is not PostgreSQL and does not prove SQL/lock behavior on a server.
type mentorStoreFixture struct {
	mu                                     sync.Mutex
	gate                                   chan struct{}
	state                                  mentorStoreState
	events                                 []string
	failAt                                 string
	failErr                                error
	commitUnknown                          bool
	afterCommit                            func()
	metadataSeen                           chan struct{}
	beginCount, commitCount, rollbackCount int
	badProtocol                            bool
}
type mentorStoreTxFixture struct {
	pgx.Tx
	db                                 *mentorStoreFixture
	next                               mentorStoreState
	settings, metadata, locked, closed bool
}
type mentorStoreRow struct {
	values []any
	err    error
}

func (row mentorStoreRow) Scan(dest ...any) error {
	if row.err != nil {
		return row.err
	}
	if len(dest) != len(row.values) {
		return errors.New("fixture scan arity mismatch")
	}
	for i, value := range row.values {
		target := reflect.ValueOf(dest[i]).Elem()
		source := reflect.ValueOf(value)
		if !source.IsValid() || !source.Type().AssignableTo(target.Type()) {
			return errors.New("fixture scan type mismatch")
		}
		target.Set(source)
	}
	return nil
}
func newMentorStoreFixture() *mentorStoreFixture {
	db := &mentorStoreFixture{gate: make(chan struct{}, 1), metadataSeen: make(chan struct{}, 16), state: mentorStoreState{receipts: map[string]mentorStoredFixture{}, fences: map[string]mentorStoredFixture{}, physical: map[string]mentorPhysicalFixture{}, student: "student", admin: "admin", adminCount: 1, scopeCount: 1, scopeValid: 1, roleID: mentorStoreRoleID, serviceID: mentorStoreServiceID}}
	db.gate <- struct{}{}
	return db
}
func (db *mentorStoreFixture) event(kind string) bool {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.events = append(db.events, kind)
	return db.failAt == kind
}
func (db *mentorStoreFixture) failure() error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.failErr != nil {
		return db.failErr
	}
	return errors.New("private database diagnostic")
}
func (db *mentorStoreFixture) BeginTx(ctx context.Context, options pgx.TxOptions) (pgx.Tx, error) {
	if db.event("begin") {
		return nil, db.failure()
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	db.beginCount++
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 5*time.Second || options.IsoLevel != pgx.ReadCommitted || options.AccessMode != pgx.ReadWrite {
		db.badProtocol = true
		return nil, errors.New("transaction bounds/options missing")
	}
	return &mentorStoreTxFixture{db: db}, nil
}
func (tx *mentorStoreTxFixture) Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	kind := mentorStoreQueryKind(query)
	if tx.db.event(kind) {
		return pgconn.CommandTag{}, tx.db.failure()
	}
	switch kind {
	case "settings":
		if !strings.Contains(query, "lock_timeout") || !strings.Contains(query, "statement_timeout") || !strings.Contains(query, "search_path") {
			return pgconn.CommandTag{}, errors.New("missing bounded settings")
		}
		if !strings.Contains(query, "'search_path', 'pg_catalog,public,pg_temp', true") {
			return pgconn.CommandTag{}, errors.New("implicit temporary schema can shadow canonical Admin")
		}
		tx.settings = true
		return pgconn.NewCommandTag("SET"), nil
	case "metadata_locks":
		if !tx.settings || !strings.Contains(query, "public.role, public.service, public.service_role, public.mentor_role_scope") || !strings.Contains(query, "IN SHARE MODE") {
			return pgconn.CommandTag{}, errors.New("wrong metadata lock order")
		}
		tx.metadata = true
		select {
		case tx.db.metadataSeen <- struct{}{}:
		default:
		}
		return pgconn.NewCommandTag("LOCK TABLE"), nil
	case "state_locks":
		if !tx.metadata || !strings.Contains(query, "public.principal_role, public.mentor_role_command_receipt, public.mentor_role_fence") || !strings.Contains(query, "IN SHARE ROW EXCLUSIVE MODE") {
			return pgconn.CommandTag{}, errors.New("wrong state lock order")
		}
		select {
		case <-tx.db.gate:
		case <-ctx.Done():
			return pgconn.CommandTag{}, ctx.Err()
		}
		tx.locked = true
		tx.db.mu.Lock()
		tx.next = tx.db.state.copy()
		tx.db.mu.Unlock()
		return pgconn.NewCommandTag("LOCK TABLE"), nil
	}
	if !tx.locked || strings.Contains(query, "FOR UPDATE") {
		return pgconn.CommandTag{}, errors.New("mutation outside table fence")
	}
	switch kind {
	case "receipt_insert":
		if len(args) != 12 {
			return pgconn.CommandTag{}, errors.New("receipt arguments mismatch")
		}
		r := mentorFixtureRecord(args)
		if _, exists := tx.next.receipts[r.command.RequestID]; exists {
			return pgconn.CommandTag{}, &pgconn.PgError{Code: "23505"}
		}
		for _, old := range tx.next.receipts {
			if old.command.ApplicationID == r.command.ApplicationID && old.command.ApplicationRevision == r.command.ApplicationRevision {
				return pgconn.CommandTag{}, &pgconn.PgError{Code: "23505"}
			}
		}
		if !domain.ValidMentorRoleCommand(r.command) || r.roleID != tx.next.roleID || r.serviceID != tx.next.serviceID {
			return pgconn.CommandTag{}, errors.New("receipt binding invalid")
		}
		tx.next.receipts[r.command.RequestID] = r
		tx.next.writes++
		return pgconn.NewCommandTag("INSERT 0 1"), nil
	case "assignment_insert", "assignment_delete":
		if !mentorFixtureScopeArgs(args, tx.next.roleID, tx.next.serviceID) {
			return pgconn.CommandTag{}, errors.New("assignment escaped Mentor scope")
		}
		target := args[0].(string)
		row := tx.next.physical[target]
		if kind == "assignment_insert" {
			if row.total != 0 {
				return pgconn.CommandTag{}, &pgconn.PgError{Code: "23505"}
			}
			tx.next.physical[target] = mentorPhysicalFixture{1, 1}
			tx.next.writes++
			return pgconn.NewCommandTag("INSERT 0 1"), nil
		}
		removed := row.mentor
		if removed > 0 {
			row.total -= removed
			row.mentor = 0
			tx.next.physical[target] = row
			tx.next.writes++
		}
		return pgconn.NewCommandTag("DELETE " + strconv.FormatInt(removed, 10)), nil
	case "fence_insert":
		if len(args) != 9 {
			return pgconn.CommandTag{}, errors.New("fence insert arguments mismatch")
		}
		request := args[8].(string)
		r, exists := tx.next.receipts[request]
		if !exists {
			return pgconn.CommandTag{}, errors.New("dangling new fence")
		}
		if _, exists = tx.next.fences[r.command.ApplicationID]; exists {
			return pgconn.CommandTag{}, &pgconn.PgError{Code: "23505"}
		}
		for _, old := range tx.next.fences {
			if old.command.TargetUserID == r.command.TargetUserID {
				return pgconn.CommandTag{}, &pgconn.PgError{Code: "23505"}
			}
		}
		want := []any{r.command.ApplicationID, r.command.Issuer, r.command.TargetUserID, r.command.Role, r.command.Service, r.roleID, r.serviceID, int64(r.command.ApplicationRevision), r.command.RequestID}
		if !reflect.DeepEqual(args, want) {
			return pgconn.CommandTag{}, errors.New("fence foreign binding")
		}
		tx.next.fences[r.command.ApplicationID] = r
		tx.next.writes++
		return pgconn.NewCommandTag("INSERT 0 1"), nil
	case "fence_update":
		if len(args) != 7 {
			return pgconn.CommandTag{}, errors.New("fence update arguments mismatch")
		}
		application := args[3].(string)
		old, exists := tx.next.fences[application]
		if !exists || old.command.Issuer != args[4] || int64(old.command.ApplicationRevision) != args[5] || old.command.RequestID != args[6] {
			return pgconn.NewCommandTag("UPDATE 0"), nil
		}
		r, exists := tx.next.receipts[args[2].(string)]
		if !exists || r.command.ApplicationID != application || r.command.TargetUserID != old.command.TargetUserID || r.roleID != old.roleID || r.serviceID != old.serviceID || old.command.ApplicationRevision != 2 || r.command.Decision != "SUSPEND" {
			return pgconn.CommandTag{}, errors.New("invalid fence transition")
		}
		tx.next.fences[application] = r
		tx.next.writes++
		return pgconn.NewCommandTag("UPDATE 1"), nil
	default:
		return pgconn.CommandTag{}, errors.New("unexpected SQL mutation")
	}
}
func (tx *mentorStoreTxFixture) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	kind := mentorStoreQueryKind(query)
	if tx.db.event(kind) {
		return mentorStoreRow{err: tx.db.failure()}
	}
	if !tx.locked || strings.Contains(query, "FOR UPDATE") {
		return mentorStoreRow{err: errors.New("query before serialization or unexpected row lock")}
	}
	switch kind {
	case "scope":
		return mentorStoreRow{values: []any{tx.next.scopeCount, tx.next.scopeValid, tx.next.roleID, tx.next.serviceID}}
	case "admin":
		if !strings.Contains(query, "FROM public.principal_role pr") || !strings.Contains(query, "JOIN public.role r") {
			return mentorStoreRow{err: errors.New("canonical Admin query is not schema-qualified")}
		}
		want := []any{mentorStoreAdmin, "user", defaultTenantID, defaultServiceID, defaultScopeKind, defaultResourceID}
		if !reflect.DeepEqual(args, want) {
			return mentorStoreRow{err: errors.New("noncanonical Admin scope")}
		}
		return mentorStoreRow{values: []any{tx.next.admin, tx.next.adminCount}}
	case "receipt":
		if len(args) != 2 || args[0] != domain.MentorRoleProofIssuer {
			return mentorStoreRow{err: errors.New("wrong receipt key")}
		}
		r, exists := tx.next.receipts[args[1].(string)]
		if !exists {
			return mentorStoreRow{err: pgx.ErrNoRows}
		}
		return mentorStoreRow{values: mentorFixtureValues(r)}
	case "application_fence", "target_fence":
		if !strings.Contains(query, "LEFT JOIN public.mentor_role_command_receipt") {
			return mentorStoreRow{err: errors.New("dangling fence could disappear")}
		}
		var r mentorStoredFixture
		found := false
		if kind == "application_fence" {
			r, found = tx.next.fences[args[0].(string)]
		} else {
			if len(args) != 3 || args[1] != domain.MentorRole || args[2] != domain.MentorRoleService {
				return mentorStoreRow{err: errors.New("wrong target fence scope")}
			}
			for _, f := range tx.next.fences {
				if f.command.TargetUserID == args[0] {
					r, found = f, true
					break
				}
			}
		}
		if !found {
			return mentorStoreRow{err: pgx.ErrNoRows}
		}
		receipt, exists := tx.next.receipts[r.command.RequestID]
		present := exists && receipt == r
		values := mentorFixtureValues(r)
		if !present {
			values[2], values[6], values[7] = "", "", ""
		}
		return mentorStoreRow{values: append(values, present)}
	case "physical":
		if len(args) != 7 || args[1] != "user" || args[2] != defaultTenantID || args[3] != tx.next.serviceID || args[4] != defaultScopeKind || args[5] != defaultResourceID || args[6] != tx.next.roleID {
			return mentorStoreRow{err: errors.New("physical read escaped exact scope")}
		}
		row := tx.next.physical[args[0].(string)]
		return mentorStoreRow{values: []any{row.total, row.mentor}}
	default:
		return mentorStoreRow{err: errors.New("unexpected SQL read")}
	}
}
func (tx *mentorStoreTxFixture) Commit(ctx context.Context) error {
	failed := tx.db.event("commit")
	if !tx.locked || ctx.Err() != nil {
		return errors.New("commit without current transaction")
	}
	if failed {
		return tx.db.failure()
	}
	tx.db.mu.Lock()
	tx.db.state = tx.next.copy()
	tx.db.commitCount++
	unknown := tx.db.commitUnknown
	tx.db.commitUnknown = false
	tx.db.mu.Unlock()
	tx.release()
	if unknown {
		return errors.New("uncertain commit ACK")
	}
	if tx.db.afterCommit != nil {
		tx.db.afterCommit()
	}
	return nil
}
func (tx *mentorStoreTxFixture) Rollback(ctx context.Context) error {
	if tx.closed {
		return pgx.ErrTxClosed
	}
	tx.db.event("rollback")
	tx.db.mu.Lock()
	tx.db.rollbackCount++
	deadline, ok := ctx.Deadline()
	if ctx.Err() != nil || !ok || time.Until(deadline) > time.Second {
		tx.db.badProtocol = true
	}
	tx.db.mu.Unlock()
	tx.release()
	return nil
}
func (tx *mentorStoreTxFixture) release() {
	if tx.closed {
		return
	}
	tx.closed = true
	if tx.locked {
		tx.db.gate <- struct{}{}
		tx.locked = false
	}
}
func mentorStoreQueryKind(q string) string {
	switch {
	case strings.Contains(q, "set_config"):
		return "settings"
	case strings.HasPrefix(q, "LOCK TABLE public.role,"):
		return "metadata_locks"
	case strings.HasPrefix(q, "LOCK TABLE public.principal_role,"):
		return "state_locks"
	case strings.Contains(q, "FROM public.mentor_role_scope"):
		return "scope"
	case strings.Contains(q, "FROM principal_role pr"), strings.Contains(q, "FROM public.principal_role pr"):
		return "admin"
	case strings.HasPrefix(q, "INSERT INTO public.mentor_role_command_receipt"):
		return "receipt_insert"
	case strings.HasPrefix(q, "INSERT INTO public.mentor_role_fence"):
		return "fence_insert"
	case strings.HasPrefix(q, "UPDATE public.mentor_role_fence"):
		return "fence_update"
	case strings.HasPrefix(q, "INSERT INTO public.principal_role"):
		return "assignment_insert"
	case strings.HasPrefix(q, "DELETE FROM public.principal_role"):
		return "assignment_delete"
	case strings.Contains(q, "FROM public.mentor_role_fence f") && strings.Contains(q, "WHERE f.application_id=$1"):
		return "application_fence"
	case strings.Contains(q, "FROM public.mentor_role_fence f") && strings.Contains(q, "WHERE f.target_user_id=$1"):
		return "target_fence"
	case strings.Contains(q, "FROM public.mentor_role_command_receipt"):
		return "receipt"
	case strings.Contains(q, "FROM public.principal_role"):
		return "physical"
	default:
		return "unknown"
	}
}
func mentorFixtureValues(r mentorStoredFixture) []any {
	return []any{r.command.Issuer, r.command.RequestID, r.command.AdminID, r.command.TargetUserID, r.command.ApplicationID, int64(r.command.ApplicationRevision), r.command.Decision, r.command.DecisionDigest, r.command.Role, r.command.Service, r.roleID, r.serviceID}
}
func mentorFixtureRecord(a []any) mentorStoredFixture {
	return mentorStoredFixture{command: domain.MentorRoleCommand{Issuer: a[0].(string), RequestID: a[1].(string), AdminID: a[2].(string), TargetUserID: a[3].(string), ApplicationID: a[4].(string), ApplicationRevision: uint64(a[5].(int64)), Decision: a[6].(string), DecisionDigest: a[7].(string), Role: a[8].(string), Service: a[9].(string)}, roleID: a[10].(string), serviceID: a[11].(string)}
}
func mentorFixtureScopeArgs(a []any, role, service string) bool {
	return len(a) == 7 && a[1] == "user" && a[2] == role && a[3] == defaultTenantID && a[4] == service && a[5] == defaultScopeKind && a[6] == defaultResourceID
}

func mentorStoreProof(decision string, revision uint64) domain.MentorRoleProof {
	request := "00000000-0000-4000-8000-000000000d01"
	if decision == "SUSPEND" {
		request = "00000000-0000-4000-8000-000000000d02"
	}
	command := domain.MentorRoleCommand{Issuer: domain.MentorRoleProofIssuer, AdminID: mentorStoreAdmin, TargetUserID: mentorStoreTarget, ApplicationID: mentorStoreApplication, ApplicationRevision: revision, Decision: decision, RequestID: request, Role: domain.MentorRole, Service: domain.MentorRoleService}
	command = mentorStoreDigest(command)
	now := time.Now().Unix()
	return domain.MentorRoleProof{Command: command, JWTID: "00000000-0000-4000-8000-000000000e01", ProofDigest: strings.Repeat("a", 64), IssuedAt: now, ExpiresAt: now + 30}
}
func mentorStoreDigest(c domain.MentorRoleCommand) domain.MentorRoleCommand {
	h := sha256.Sum256([]byte(c.Decision + "|" + c.AdminID + "|" + c.ApplicationID + "|" + c.RequestID + "|" + strconv.FormatUint(c.ApplicationRevision-1, 10)))
	c.DecisionDigest = hex.EncodeToString(h[:])
	return c
}
func mentorStoreRecheck(db *mentorStoreFixture, p domain.MentorRoleProof) domain.MentorRoleProofRevalidator {
	return func(ctx context.Context) (domain.MentorRoleProof, error) {
		db.event("verify")
		if ctx == nil || ctx.Err() != nil {
			return domain.MentorRoleProof{}, domain.ErrUnauthenticated
		}
		return p, nil
	}
}
func applyMentorFixture(t *testing.T, db *mentorStoreFixture, p domain.MentorRoleProof) domain.MentorRolePlan {
	t.Helper()
	plan, err := NewMentorRoleStore(db).ApplyMentorRole(context.Background(), p, mentorStoreRecheck(db, p))
	if err != nil {
		t.Fatalf("valid atomic Mentor command failed: %v", err)
	}
	return plan
}
func deniedMentorFixture(t *testing.T, db *mentorStoreFixture, p domain.MentorRoleProof, want error) {
	t.Helper()
	plan, err := NewMentorRoleStore(db).ApplyMentorRole(context.Background(), p, mentorStoreRecheck(db, p))
	if !errors.Is(err, want) || plan != (domain.MentorRolePlan{}) {
		t.Fatalf("expected zero plan/%v; got %v", want, err)
	}
}

func TestMentorRoleStoreApprovalReplaySuspensionAndHistoricalReceipt(t *testing.T) {
	db := newMentorStoreFixture()
	approve := mentorStoreProof("APPROVE", 2)
	first := applyMentorFixture(t, db, approve)
	if !first.Write || first.Replay || !first.Current.Active || db.state.student != "student" || db.state.physical[mentorStoreTarget] != (mentorPhysicalFixture{1, 1}) || len(db.state.receipts) != 1 || len(db.state.fences) != 1 {
		t.Fatal("approval was not one scoped atomic write")
	}
	want := []string{"verify", "begin", "settings", "metadata_locks", "state_locks", "verify", "scope", "admin", "receipt", "application_fence", "target_fence", "physical", "receipt_insert", "assignment_insert", "fence_insert", "verify", "commit"}
	if !reflect.DeepEqual(db.events, want) {
		t.Fatalf("wrong transaction protocol order: %v", db.events)
	}
	writes := db.state.writes
	replay := applyMentorFixture(t, db, approve)
	if !replay.Replay || replay.Write || replay.Receipt != first.Receipt || db.state.writes != writes {
		t.Fatal("exact retry rewrote state")
	}
	suspend := mentorStoreProof("SUSPEND", 4)
	revoked := applyMentorFixture(t, db, suspend)
	if revoked.Current.Active || !revoked.Current.Suspended || db.state.physical[mentorStoreTarget].total != 0 || db.state.student != "student" {
		t.Fatal("suspension did not revoke only Mentor scope")
	}
	writes = db.state.writes
	historical := applyMentorFixture(t, db, approve)
	if !historical.Replay || historical.Write || !historical.Receipt.Applied.Active || historical.Current.Active || historical.Receipt != first.Receipt || db.state.writes != writes {
		t.Fatal("historical receipt replay resurrected a revoked role")
	}
}

func TestMentorRoleStoreRevokeFirstConflictsAndBilateralBinding(t *testing.T) {
	db := newMentorStoreFixture()
	suspend := mentorStoreProof("SUSPEND", 3)
	plan := applyMentorFixture(t, db, suspend)
	if plan.Current.Active || !plan.Current.Suspended || len(db.state.receipts) != 1 {
		t.Fatal("revoke-first did not commit tombstone")
	}
	deniedMentorFixture(t, db, mentorStoreProof("APPROVE", 2), domain.ErrMentorRoleStaleRevision)
	changed := mentorStoreProof("APPROVE", 2)
	changed.Command.ApplicationID = "00000000-0000-4000-8000-000000000c02"
	changed.Command = mentorStoreDigest(changed.Command)
	deniedMentorFixture(t, db, changed, domain.ErrMentorRoleConflict)
	changed = suspend
	changed.Command.TargetUserID = "00000000-0000-4000-8000-000000000b02"
	deniedMentorFixture(t, db, changed, domain.ErrMentorRoleConflict)
	changed = suspend
	changed.Command.RequestID = "00000000-0000-4000-8000-000000000d03"
	changed.Command = mentorStoreDigest(changed.Command)
	deniedMentorFixture(t, db, changed, domain.ErrMentorRoleConflict)
	if db.state.student != "student" || db.state.physical[mentorStoreTarget].total != 0 || len(db.state.receipts) != 1 {
		t.Fatal("denied commands changed state")
	}
}

func TestMentorRoleStoreRejectsPhysicalMetadataAndHistoryDriftWithoutRepair(t *testing.T) {
	approve := mentorStoreProof("APPROVE", 2)
	for _, tc := range []struct {
		name  string
		setup func(*mentorStoreFixture)
		want  error
	}{
		{"missing scope", func(d *mentorStoreFixture) { d.state.scopeCount = 0 }, domain.ErrAuthorityUnavailable},
		{"multiple scope", func(d *mentorStoreFixture) { d.state.scopeCount = 2 }, domain.ErrAuthorityUnavailable},
		{"wrong metadata", func(d *mentorStoreFixture) { d.state.scopeValid = 0 }, domain.ErrAuthorityUnavailable},
		{"core service", func(d *mentorStoreFixture) { d.state.serviceID = defaultServiceID }, domain.ErrAuthorityUnavailable},
		{"noncanonical role ID", func(d *mentorStoreFixture) { d.state.roleID = "bad" }, domain.ErrAuthorityUnavailable},
		{"unowned existing Mentor grant", func(d *mentorStoreFixture) { d.state.physical[mentorStoreTarget] = mentorPhysicalFixture{1, 1} }, domain.ErrMentorRoleConflict},
		{"unowned foreign role", func(d *mentorStoreFixture) { d.state.physical[mentorStoreTarget] = mentorPhysicalFixture{1, 0} }, domain.ErrMentorRoleConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newMentorStoreFixture()
			tc.setup(d)
			before := d.state.copy()
			deniedMentorFixture(t, d, approve, tc.want)
			if !reflect.DeepEqual(d.state, before) {
				t.Fatal("denied state was repaired")
			}
		})
	}
	for _, tc := range []struct {
		name   string
		mutate func(*mentorStoreFixture)
	}{
		{"missing physical grant", func(d *mentorStoreFixture) { d.state.physical[mentorStoreTarget] = mentorPhysicalFixture{} }},
		{"multiple physical grants", func(d *mentorStoreFixture) { d.state.physical[mentorStoreTarget] = mentorPhysicalFixture{2, 1} }},
		{"changed pinned IDs", func(d *mentorStoreFixture) { d.state.roleID = "00000000-0000-4000-8000-000000000f03" }},
		{"dangling receipt", func(d *mentorStoreFixture) { delete(d.state.receipts, approve.Command.RequestID) }},
		{"corrupt receipt digest", func(d *mentorStoreFixture) {
			r := d.state.receipts[approve.Command.RequestID]
			r.command.DecisionDigest = strings.Repeat("0", 64)
			d.state.receipts[approve.Command.RequestID] = r
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newMentorStoreFixture()
			applyMentorFixture(t, d, approve)
			tc.mutate(d)
			before := d.state.copy()
			deniedMentorFixture(t, d, approve, domain.ErrMentorRoleInvalidSnapshot)
			if !reflect.DeepEqual(d.state, before) {
				t.Fatal("existing drift was silently healed")
			}
		})
	}
}

func TestMentorRoleStoreCurrentAdminIsCheckedBeforeHistoryIncludingReplay(t *testing.T) {
	for _, role := range []string{"", "student", "moderator", "Admin"} {
		d := newMentorStoreFixture()
		d.state.admin = role
		deniedMentorFixture(t, d, mentorStoreProof("APPROVE", 2), domain.ErrMentorRoleForbidden)
		if strings.Contains(strings.Join(d.events, ","), "receipt") {
			t.Fatal("non-admin reached command history")
		}
	}
	d := newMentorStoreFixture()
	d.state.adminCount = 2
	deniedMentorFixture(t, d, mentorStoreProof("APPROVE", 2), domain.ErrAuthorityUnavailable)
	d = newMentorStoreFixture()
	d.state.adminCount = 0
	deniedMentorFixture(t, d, mentorStoreProof("APPROVE", 2), domain.ErrMentorRoleForbidden)
	d = newMentorStoreFixture()
	approve := mentorStoreProof("APPROVE", 2)
	applyMentorFixture(t, d, approve)
	d.state.admin = "student"
	before := d.state.copy()
	deniedMentorFixture(t, d, approve, domain.ErrMentorRoleForbidden)
	if !reflect.DeepEqual(d.state, before) {
		t.Fatal("historical receipt bypassed current Admin")
	}
}

func TestMentorRoleStoreFailuresRollbackEveryTransactionStage(t *testing.T) {
	approve := mentorStoreProof("APPROVE", 2)
	for _, stage := range []string{"begin", "settings", "metadata_locks", "state_locks", "scope", "admin", "receipt", "application_fence", "target_fence", "physical", "receipt_insert", "assignment_insert", "fence_insert", "commit"} {
		t.Run(stage, func(t *testing.T) {
			d := newMentorStoreFixture()
			before := d.state.copy()
			d.failAt = stage
			deniedMentorFixture(t, d, approve, domain.ErrAuthorityUnavailable)
			if !reflect.DeepEqual(d.state, before) {
				t.Fatal("failed transaction committed a partial change")
			}
			if stage != "begin" && d.rollbackCount != 1 {
				t.Fatal("failed transaction was not rolled back")
			}
		})
	}
	for _, stage := range []string{"assignment_delete", "fence_update"} {
		t.Run(stage, func(t *testing.T) {
			d := newMentorStoreFixture()
			applyMentorFixture(t, d, approve)
			before := d.state.copy()
			d.failAt = stage
			deniedMentorFixture(t, d, mentorStoreProof("SUSPEND", 4), domain.ErrAuthorityUnavailable)
			if !reflect.DeepEqual(d.state, before) {
				t.Fatal("failed revoke committed a partial change")
			}
		})
	}
}

func TestMentorRoleStoreFreshProofRequiredAtEveryBoundary(t *testing.T) {
	proof := mentorStoreProof("APPROVE", 2)
	for _, boundary := range []int32{1, 2, 3} {
		for _, changed := range []bool{false, true} {
			d := newMentorStoreFixture()
			var calls atomic.Int32
			recheck := func(ctx context.Context) (domain.MentorRoleProof, error) {
				if limit, ok := ctx.Deadline(); !ok || time.Until(limit) > 5*time.Second {
					t.Error("entire store call lacks bounded deadline")
				}
				current := proof
				if calls.Add(1) == boundary {
					if !changed {
						return domain.MentorRoleProof{}, domain.ErrUnauthenticated
					}
					current.JWTID = "00000000-0000-4000-8000-000000000e02"
				}
				return current, nil
			}
			plan, err := NewMentorRoleStore(d).ApplyMentorRole(context.Background(), proof, recheck)
			if !errors.Is(err, domain.ErrUnauthenticated) || plan != (domain.MentorRolePlan{}) || len(d.state.receipts) != 0 || d.state.physical[mentorStoreTarget].total != 0 {
				t.Fatal("stale or changed proof passed transaction boundary")
			}
		}
	}
	for _, invalid := range []domain.MentorRoleProof{{}, {Command: proof.Command}} {
		d := newMentorStoreFixture()
		plan, err := NewMentorRoleStore(d).ApplyMentorRole(context.Background(), invalid, mentorStoreRecheck(d, invalid))
		if err == nil || plan != (domain.MentorRolePlan{}) || d.beginCount != 0 {
			t.Fatal("invalid proof shape reached transaction")
		}
	}
	d := newMentorStoreFixture()
	if _, err := NewMentorRoleStore(d).ApplyMentorRole(context.Background(), proof, nil); err == nil || d.beginCount != 0 {
		t.Fatal("nil revalidator reached transaction")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewMentorRoleStore(d).ApplyMentorRole(ctx, proof, mentorStoreRecheck(d, proof)); err == nil || d.beginCount != 0 {
		t.Fatal("cancelled caller reached transaction")
	}
	var typedNil *mentorStoreFixture
	for _, store := range []*MentorRoleStore{nil, {}, NewMentorRoleStore(typedNil)} {
		if plan, err := store.ApplyMentorRole(context.Background(), proof, func(context.Context) (domain.MentorRoleProof, error) { return proof, nil }); err == nil || plan != (domain.MentorRolePlan{}) {
			t.Fatal("missing database accepted")
		}
	}
}

func TestMentorRoleStoreConcurrentCommandsAndPostLockAdminCurrentness(t *testing.T) {
	d := newMentorStoreFixture()
	proof := mentorStoreProof("APPROVE", 2)
	var wg sync.WaitGroup
	results := make(chan domain.MentorRolePlan, 8)
	failures := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, e := NewMentorRoleStore(d).ApplyMentorRole(context.Background(), proof, mentorStoreRecheck(d, proof))
			if e != nil {
				failures <- e
			} else {
				results <- p
			}
		}()
	}
	wg.Wait()
	close(results)
	close(failures)
	for e := range failures {
		t.Fatalf("concurrent command failed: %v", e)
	}
	writes := 0
	replays := 0
	for p := range results {
		if p.Write {
			writes++
		}
		if p.Replay {
			replays++
		}
	}
	if writes != 1 || replays != 7 || len(d.state.receipts) != 1 || d.state.physical[mentorStoreTarget] != (mentorPhysicalFixture{1, 1}) {
		t.Fatal("concurrent retries did not converge to one commit")
	}
	d = newMentorStoreFixture()
	<-d.gate
	done := make(chan error, 1)
	go func() {
		_, e := NewMentorRoleStore(d).ApplyMentorRole(context.Background(), proof, mentorStoreRecheck(d, proof))
		done <- e
	}()
	select {
	case <-d.metadataSeen:
	case <-time.After(time.Second):
		t.Fatal("store never reached lock boundary")
	}
	d.mu.Lock()
	d.state.admin = "student"
	d.mu.Unlock()
	d.gate <- struct{}{}
	if e := <-done; !errors.Is(e, domain.ErrMentorRoleForbidden) || len(d.state.receipts) != 0 {
		t.Fatal("pre-lock Admin snapshot authorized after revocation")
	}
}

func TestMentorRoleStoreUncertainCommitReturnsNoSuccessAndFreshReplayRecovers(t *testing.T) {
	d := newMentorStoreFixture()
	proof := mentorStoreProof("APPROVE", 2)
	d.commitUnknown = true
	deniedMentorFixture(t, d, proof, domain.ErrAuthorityUnavailable)
	if len(d.state.receipts) != 1 || d.state.physical[mentorStoreTarget].total != 1 {
		t.Fatal("fixture did not model lost successful commit ACK")
	}
	before := d.state.copy()
	fresh := proof
	fresh.JWTID = "00000000-0000-4000-8000-000000000e02"
	fresh.ProofDigest = strings.Repeat("b", 64)
	replay := applyMentorFixture(t, d, fresh)
	if !replay.Replay || replay.Write || !reflect.DeepEqual(d.state, before) {
		t.Fatal("fresh retry after uncertain commit changed assignment")
	}
}

func TestMentorRoleStoreClassifiesDatabaseFailuresAndBoundsCleanup(t *testing.T) {
	proof := mentorStoreProof("APPROVE", 2)
	for _, stage := range []string{"begin", "state_locks", "admin", "receipt_insert", "commit"} {
		for _, failure := range []error{context.Canceled, context.DeadlineExceeded, &pgconn.PgError{Code: "40P01"}, &pgconn.PgError{Code: "55P03"}} {
			t.Run(stage+"/"+failure.Error(), func(t *testing.T) {
				d := newMentorStoreFixture()
				d.failAt, d.failErr = stage, failure
				before := d.state.copy()
				deniedMentorFixture(t, d, proof, domain.ErrAuthorityUnavailable)
				if !reflect.DeepEqual(d.state, before) || d.badProtocol {
					t.Fatal("database failure leaked mutation or unbounded cleanup")
				}
			})
		}
	}
	for _, stage := range []string{"receipt_insert", "assignment_insert", "fence_insert"} {
		t.Run(stage+"/unique", func(t *testing.T) {
			d := newMentorStoreFixture()
			d.failAt, d.failErr = stage, &pgconn.PgError{Code: "23505"}
			before := d.state.copy()
			deniedMentorFixture(t, d, proof, domain.ErrMentorRoleConflict)
			if !reflect.DeepEqual(d.state, before) || d.badProtocol {
				t.Fatal("constraint conflict leaked a partial write")
			}
		})
	}
	d := newMentorStoreFixture()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	plan, err := NewMentorRoleStore(d).ApplyMentorRole(ctx, proof, func(context.Context) (domain.MentorRoleProof, error) {
		calls++
		if calls == 3 {
			cancel()
		}
		return proof, nil
	})
	if !errors.Is(err, domain.ErrUnauthenticated) || plan != (domain.MentorRolePlan{}) || len(d.state.receipts) != 0 || d.rollbackCount != 1 || d.badProtocol {
		t.Fatal("precommit cancellation did not safely roll back under bounded cleanup context")
	}
	d = newMentorStoreFixture()
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	d.afterCommit = cancel
	plan, err = NewMentorRoleStore(d).ApplyMentorRole(ctx, proof, mentorStoreRecheck(d, proof))
	if err != nil || !plan.Write || !plan.Current.Active || d.rollbackCount != 0 || ctx.Err() == nil {
		t.Fatal("acknowledged commit was reclassified as rollback by a later cancellation")
	}
}

func TestMentorRoleStoreConcurrentApproveAndSuspendCannotResurrect(t *testing.T) {
	for round := 0; round < 8; round++ {
		d := newMentorStoreFixture()
		approve := mentorStoreProof("APPROVE", 2)
		suspend := mentorStoreProof("SUSPEND", 4)
		start := make(chan struct{})
		results := make(chan error, 2)
		for _, proof := range []domain.MentorRoleProof{approve, suspend} {
			go func(p domain.MentorRoleProof) {
				<-start
				_, err := NewMentorRoleStore(d).ApplyMentorRole(context.Background(), p, mentorStoreRecheck(d, p))
				if err != nil && !(p.Command.Decision == "APPROVE" && errors.Is(err, domain.ErrMentorRoleStaleRevision)) {
					results <- err
					return
				}
				results <- nil
			}(proof)
		}
		close(start)
		for i := 0; i < 2; i++ {
			if err := <-results; err != nil {
				t.Fatalf("opposing concurrent command failed unexpectedly: %v", err)
			}
		}
		if d.state.fences[mentorStoreApplication].command != suspend.Command || d.state.physical[mentorStoreTarget].total != 0 || d.state.student != "student" {
			t.Fatal("concurrent approval resurrected a suspended scoped assignment")
		}
	}
}

func TestMentorRoleStoreRealRSAAdmissionThroughUsecase(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := client.NewAuthMentorRoleProofVerifier(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public})))
	if err != nil {
		t.Fatal(err)
	}
	proof := mentorStoreProof("APPROVE", 2)
	c := proof.Command
	claims := map[string]any{"iss": c.Issuer, "aud": domain.MentorRoleProofAudience, "sub": c.AdminID, "typ": domain.MentorRoleProofType, "purpose": domain.MentorRoleProofPurpose, "target_user_id": c.TargetUserID, "application_id": c.ApplicationID, "application_revision": c.ApplicationRevision, "decision": c.Decision, "request_id": c.RequestID, "decision_digest": c.DecisionDigest, "role": c.Role, "service": c.Service, "jti": proof.JWTID, "iat": proof.IssuedAt, "exp": proof.ExpiresAt}
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	input := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString(raw)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	token := input + "." + base64.RawURLEncoding.EncodeToString(sig)
	d := newMentorStoreFixture()
	mutation := usecase.NewMentorRoleMutation(verifier, NewMentorRoleStore(d))
	plan, err := mutation.Apply(context.Background(), token)
	if err != nil || !plan.Write || !plan.Current.Active {
		t.Fatalf("real RSA/usecase/PG-method path failed: %v", err)
	}
	begins := d.beginCount
	if p, e := mutation.Apply(context.Background(), token+"x"); e == nil || p != (domain.MentorRolePlan{}) || d.beginCount != begins {
		t.Fatal("tampered real proof reached database")
	}
}
