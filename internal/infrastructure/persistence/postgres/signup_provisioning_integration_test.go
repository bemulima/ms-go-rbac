package repo_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/example/ms-rbac-service/internal/domain"
	"github.com/example/ms-rbac-service/internal/infrastructure/client"
	repo "github.com/example/ms-rbac-service/internal/infrastructure/persistence/postgres"
	"github.com/example/ms-rbac-service/internal/usecase"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This opt-in boundary uses the real proof verifier, application and PostgreSQL
// repository with local unit keys. It does not claim Auth issuance or a full main.
// The root creates/migrates the isolated database. Receipts and test data remain.
func signupSQLPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("RBAC_SIGNUP_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("opt-in signup SQL test requires root-owned RBAC_SIGNUP_TEST_DATABASE_URL")
	}
	u, err := url.Parse(dsn)
	loopback := func(host string) bool {
		ip := net.ParseIP(host)
		return host == "localhost" || (ip != nil && ip.IsLoopback())
	}
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || !loopback(u.Hostname()) {
		t.Fatal("signup SQL test requires one loopback database URL")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil || !loopback(cfg.Host) || !strings.HasSuffix(cfg.Database, "_test") {
		t.Fatal("signup SQL test requires an owned database ending in _test")
	}
	for _, fallback := range cfg.Fallbacks {
		if !loopback(fallback.Host) {
			t.Fatal("non-loopback database fallback forbidden")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("cannot open isolated signup test database")
	}
	t.Cleanup(pool.Close)
	var database, server string
	if pool.QueryRow(ctx, `SELECT current_database(),host(inet_server_addr())`).Scan(&database, &server) != nil || database != cfg.Database {
		t.Fatal("connected signup database differs from owned store")
	}
	actual := net.ParseIP(server)
	expectedText := os.Getenv("RBAC_SIGNUP_POSTGRES_EXPECTED_SERVER_IP")
	if expectedText == "" {
		expectedText = os.Getenv("T16_POSTGRES_EXPECTED_SERVER_IP")
	}
	expected := net.ParseIP(expectedText)
	if (expectedText != "" && expected == nil) || actual == nil || (!actual.IsLoopback() && (expected == nil || !actual.Equal(expected))) {
		t.Fatal("signup database backend is not loopback or root-attested")
	}
	var migrated bool
	if pool.QueryRow(ctx, `SELECT to_regclass('public.signup_provisioning_receipt') IS NOT NULL`).Scan(&migrated) != nil || !migrated {
		t.Fatal("root must apply migration 003 before SQL test")
	}
	return pool
}

func signupSQLUUID(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal("cannot create isolated unit principal")
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func signupSQLGrant(principal, operation string) domain.SignupGrant {
	now := time.Now().Unix()
	return domain.SignupGrant{Version: 1, Issuer: domain.SignupIssuer, Audience: domain.SignupAudience, Purpose: domain.SignupPurpose, Subject: "rbac.assign-role",
		OperationID: operation, PrincipalID: principal, Role: domain.SignupRole, PrincipalKind: domain.SignupKind, TenantID: domain.SignupTenantID,
		ServiceID: domain.SignupServiceID, ResourceKind: domain.SignupResourceKind, ResourceID: domain.SignupResourceID, IssuedAt: now, ExpiresAt: now + 60}
}

func signupSQLProof(private ed25519.PrivateKey, grant domain.SignupGrant) []byte {
	payload, _ := json.Marshal(grant)
	data, _ := json.Marshal(map[string]string{"key_id": domain.SignupProofKeyID, "payload": base64.StdEncoding.EncodeToString(payload), "signature": base64.StdEncoding.EncodeToString(ed25519.Sign(private, payload))})
	return data
}

func signupSQLSnapshot(t *testing.T, pool *pgxpool.Pool, principals ...string) string {
	t.Helper()
	var state string
	err := pool.QueryRow(context.Background(), `SELECT jsonb_build_object(
		'assignments',(SELECT COALESCE(jsonb_agg(jsonb_build_object('row',to_jsonb(pr),'xmin',pr.xmin::text)
			ORDER BY pr.principal_id,pr.role_id,pr.tenant_id,pr.service_id,pr.resource_kind,pr.resource_id),'[]'::jsonb)
			FROM principal_role pr WHERE principal_id::text=ANY($1::text[])),
		'receipts',(SELECT COALESCE(jsonb_agg(jsonb_build_object('row',to_jsonb(sr),'xmin',sr.xmin::text)
			ORDER BY sr.issuer,sr.operation_id),'[]'::jsonb)
			FROM signup_provisioning_receipt sr WHERE principal_id::text=ANY($1::text[])))::text`, principals).Scan(&state)
	if err != nil {
		t.Fatal("cannot snapshot isolated signup state")
	}
	return state
}

// This is explicit pre-existing test data bootstrap, not a verified grant command.
func signupSQLFixture(t *testing.T, pool *pgxpool.Pool, principal, role, tenant string) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `INSERT INTO principal_role
		(principal_id,principal_kind,role_id,tenant_id,service_id,resource_kind,resource_id)
		SELECT $1,'user',id,$3,$4,'global',$5 FROM role WHERE key=$2`, principal, role, tenant, domain.SignupServiceID, domain.SignupResourceID)
	if err != nil {
		t.Fatal("cannot bootstrap isolated pre-existing role fixture")
	}
}

func TestSignupProvisioningSQLReceiptReplayConflictsAndScope(t *testing.T) {
	pool := signupSQLPool(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("cannot generate local unit key")
	}
	verifier, err := client.NewSignupProofVerifier(base64.StdEncoding.EncodeToString(public))
	if err != nil {
		t.Fatal(err)
	}
	uc := usecase.NewSignupProvisioner(verifier, repo.NewSignupProvisioningRepository(pool))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	principal, operation := signupSQLUUID(t), signupSQLUUID(t)
	grant := signupSQLGrant(principal, operation)
	proof := signupSQLProof(private, grant)
	if err := uc.Provision(ctx, grant.Subject, proof); err != nil {
		t.Fatal("canonical signed student provisioning failed")
	}
	var assignments, receipts int
	if pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM principal_role pr JOIN role r ON r.id=pr.role_id WHERE pr.principal_id=$1 AND r.key='student'
		AND pr.principal_kind='user' AND pr.tenant_id=$2 AND pr.service_id=$3 AND pr.resource_kind='global' AND pr.resource_id=$4),
		(SELECT count(*) FROM signup_provisioning_receipt WHERE issuer=$5 AND operation_id=$6 AND principal_id=$1)`,
		principal, domain.SignupTenantID, domain.SignupServiceID, domain.SignupResourceID, domain.SignupIssuer, operation).Scan(&assignments, &receipts) != nil || assignments != 1 || receipts != 1 {
		t.Fatal("atomic canonical assignment/receipt missing")
	}
	before := signupSQLSnapshot(t, pool, principal)
	for i := 0; i < 2; i++ {
		if uc.Provision(ctx, grant.Subject, proof) != nil {
			t.Fatal("exact signed replay failed")
		}
	}
	if signupSQLSnapshot(t, pool, principal) != before {
		t.Fatal("replay rewrote assignment or receipt")
	}
	other := signupSQLUUID(t)
	before = signupSQLSnapshot(t, pool, principal, other)
	changed := grant
	changed.PrincipalID = other
	if err := uc.Provision(ctx, grant.Subject, signupSQLProof(private, changed)); !errors.Is(err, domain.ErrSignupConflict) {
		t.Fatal("same operation changed target was not conflicted")
	}
	changed = grant
	changed.OperationID = signupSQLUUID(t)
	if err := uc.Provision(ctx, grant.Subject, signupSQLProof(private, changed)); !errors.Is(err, domain.ErrSignupConflict) {
		t.Fatal("same principal changed operation was not conflicted")
	}
	if signupSQLSnapshot(t, pool, principal, other) != before {
		t.Fatal("binding conflict changed durable state")
	}
	for _, statement := range []string{`UPDATE signup_provisioning_receipt SET role_key=role_key WHERE principal_id=$1`, `DELETE FROM signup_provisioning_receipt WHERE principal_id=$1`} {
		if _, err := pool.Exec(ctx, statement, principal); err == nil {
			t.Fatal("receipt immutability guard missing")
		}
	}
	if signupSQLSnapshot(t, pool, principal, other) != before {
		t.Fatal("receipt immutability check changed state")
	}
	// Re-authorization must deny an expired proof even when a valid receipt exists.
	expired := grant
	expired.IssuedAt = time.Now().Unix() - 60
	expired.ExpiresAt = time.Now().Unix()
	if err := uc.Provision(ctx, grant.Subject, signupSQLProof(private, expired)); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatal("receipt bypassed proof freshness")
	}
	if signupSQLSnapshot(t, pool, principal, other) != before {
		t.Fatal("expired replay changed state")
	}

	existing := signupSQLUUID(t)
	signupSQLFixture(t, pool, existing, "user", domain.SignupTenantID)
	before = signupSQLSnapshot(t, pool, existing)
	existingGrant := signupSQLGrant(existing, signupSQLUUID(t))
	if err := uc.Provision(ctx, existingGrant.Subject, signupSQLProof(private, existingGrant)); !errors.Is(err, domain.ErrSignupConflict) {
		t.Fatal("existing different default role was replaced")
	}
	if signupSQLSnapshot(t, pool, existing) != before {
		t.Fatal("different-role denial changed state")
	}

	student := signupSQLUUID(t)
	signupSQLFixture(t, pool, student, "student", domain.SignupTenantID)
	var oldXmin, newXmin string
	if pool.QueryRow(ctx, `SELECT xmin::text FROM principal_role WHERE principal_id=$1`, student).Scan(&oldXmin) != nil {
		t.Fatal("cannot read fixture revision")
	}
	studentGrant := signupSQLGrant(student, signupSQLUUID(t))
	if uc.Provision(ctx, studentGrant.Subject, signupSQLProof(private, studentGrant)) != nil {
		t.Fatal("existing student provisioning failed")
	}
	if pool.QueryRow(ctx, `SELECT xmin::text FROM principal_role WHERE principal_id=$1`, student).Scan(&newXmin) != nil || oldXmin != newXmin {
		t.Fatal("existing student assignment was rewritten")
	}

	scoped := signupSQLUUID(t)
	signupSQLFixture(t, pool, scoped, "user", signupSQLUUID(t))
	scopedGrant := signupSQLGrant(scoped, signupSQLUUID(t))
	if uc.Provision(ctx, scopedGrant.Subject, signupSQLProof(private, scopedGrant)) != nil {
		t.Fatal("cross-scope fallback prevented exact default provisioning")
	}
	if pool.QueryRow(ctx, `SELECT count(*) FROM principal_role WHERE principal_id=$1`, scoped).Scan(&assignments) != nil || assignments != 2 {
		t.Fatal("unrelated scoped fixture was changed")
	}
}

func TestSignupProvisioningSQLConcurrentReplayAndAtomicConflict(t *testing.T) {
	pool := signupSQLPool(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("cannot generate local unit key")
	}
	verifier, err := client.NewSignupProofVerifier(base64.StdEncoding.EncodeToString(public))
	if err != nil {
		t.Fatal(err)
	}
	uc := usecase.NewSignupProvisioner(verifier, repo.NewSignupProvisioningRepository(pool))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	grant := signupSQLGrant(signupSQLUUID(t), signupSQLUUID(t))
	proof := signupSQLProof(private, grant)
	var wg sync.WaitGroup
	failures := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); failures <- uc.Provision(ctx, grant.Subject, proof) }()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal("concurrent exact replay did not converge")
		}
	}
	var assignments, receipts int
	if pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM principal_role WHERE principal_id=$1),
		(SELECT count(*) FROM signup_provisioning_receipt WHERE principal_id=$1)`, grant.PrincipalID).Scan(&assignments, &receipts) != nil || assignments != 1 || receipts != 1 {
		t.Fatal("concurrent replay duplicated durable state")
	}

	left := signupSQLGrant(signupSQLUUID(t), signupSQLUUID(t))
	right := left
	right.PrincipalID = signupSQLUUID(t)
	results := make(chan error, 2)
	for _, g := range []domain.SignupGrant{left, right} {
		wg.Add(1)
		go func(g domain.SignupGrant) {
			defer wg.Done()
			results <- uc.Provision(ctx, g.Subject, signupSQLProof(private, g))
		}(g)
	}
	wg.Wait()
	close(results)
	successes, conflicts := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, domain.ErrSignupConflict) {
			conflicts++
		} else {
			t.Fatal("unexpected concurrent binding failure")
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatal("same operation concurrent target binding was not unique")
	}
	if pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM principal_role WHERE principal_id::text=ANY($1::text[])),
		(SELECT count(*) FROM signup_provisioning_receipt WHERE operation_id=$2)`, []string{left.PrincipalID, right.PrincipalID}, left.OperationID).Scan(&assignments, &receipts) != nil || assignments != 1 || receipts != 1 {
		t.Fatal("receipt conflict did not roll back losing assignment")
	}
}
