// Package nats hosts the real RBAC provider for the opt-in T16 chain.
package nats

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	natsgo "github.com/nats-io/nats.go"

	"github.com/example/ms-rbac-service/internal/infrastructure/client"
	repo "github.com/example/ms-rbac-service/internal/infrastructure/persistence/postgres"
	"github.com/example/ms-rbac-service/internal/usecase"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestT16SignupRBACProvider uses production listeners, usecase, and PostgreSQL.
// The coordinator creates and migrates a NEW owned store with canonical roles.
// No assignment fixtures, policy changes, migration, or table reset occur here.
func TestT16SignupRBACProvider(t *testing.T) {
	if os.Getenv("T16_SERVE_RBAC") != "true" {
		t.Skip("opt-in actual RBAC provider requires T16_SERVE_RBAC=true")
	}
	dsn, natsURL, token, ready, stop := t16ProviderConfig(t, "RBAC_TEST_DATABASE_URL", "RBAC")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("cannot open owned RBAC database")
	}
	defer pool.Close()
	var database, server string
	if err := pool.QueryRow(ctx, "SELECT current_database(), host(inet_server_addr())").Scan(&database, &server); err != nil ||
		!t16ProviderStoreMatches(dsn, database, server, os.Getenv("T16_POSTGRES_EXPECTED_SERVER_IP")) {
		t.Fatal("connected RBAC database must match the configured owned store and attested backend")
	}
	var existing int64
	if err := pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM principal_role) + (SELECT count(*) FROM principal_override) +
		(SELECT count(*) FROM superadmin_principal)`).Scan(&existing); err != nil {
		t.Fatal("owned RBAC schema must be migrated by the coordinator")
	}
	if existing != 0 {
		t.Fatal("RBAC provider requires empty principal tables; no reset is performed")
	}
	var canonicalStudent bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM role WHERE key='student')`).Scan(&canonicalStudent); err != nil || !canonicalStudent {
		t.Fatal("coordinator must apply canonical RBAC reference data")
	}

	conn, err := natsgo.Connect(natsURL, natsgo.Timeout(5*time.Second), natsgo.NoReconnect())
	if err != nil {
		t.Fatal("cannot connect isolated RBAC NATS server")
	}
	defer conn.Close()
	principal := usecase.NewPrincipalRoleUsecase(repo.NewPrincipalRoleRepository(pool))
	if os.Getenv("AUTH_SIGNUP_PUBLIC_KEY") == "" {
		t.Fatal("AUTH_SIGNUP_PUBLIC_KEY is required for the signed signup provider")
	}
	verifier, err := client.NewSignupProofVerifier(os.Getenv("AUTH_SIGNUP_PUBLIC_KEY"))
	if err != nil {
		t.Fatal("invalid signed signup provider configuration")
	}
	signup := usecase.NewSignupProvisioner(verifier, repo.NewSignupProvisioningRepository(pool))
	if err := (RoleAssigner{Conn: conn,
		Subject: t16Subject(t, "T16_RBAC_ASSIGN_SUBJECT", "rbac.assign-role"),
		Queue:   "ms-go-rbac", SignupUC: signup}).Listen(); err != nil {
		t.Fatal("cannot register production RBAC assignment listener")
	}
	if err := (RoleChecker{Conn: conn,
		Subject: t16Subject(t, "T16_RBAC_CHECK_SUBJECT", "rbac.checkRole"),
		Queue:   "ms-go-rbac", PrincipalUC: principal}).Listen(); err != nil {
		t.Fatal("cannot register production RBAC readback listener")
	}
	if err := conn.FlushTimeout(5 * time.Second); err != nil {
		t.Fatal("cannot flush RBAC provider subscriptions")
	}

	control := httptest.NewServer(t16InspectHandler(token, func(ctx context.Context, id string) (any, error) {
		var result struct {
			AssignedStudent      bool  `json:"assigned_student"`
			AssignmentCount      int64 `json:"assignment_count"`
			TotalAssignmentCount int64 `json:"total_assignment_count"`
		}
		err := pool.QueryRow(ctx, `SELECT
			EXISTS(SELECT 1 FROM principal_role pr JOIN role r ON r.id=pr.role_id
				WHERE pr.principal_id=$1 AND pr.principal_kind='user' AND r.key='student'
				AND pr.tenant_id='00000000-0000-0000-0000-000000000000'
				AND pr.service_id='00000000-0000-0000-0000-000000000100'
				AND pr.resource_kind='global' AND pr.resource_id='00000000-0000-0000-0000-000000000000'),
			(SELECT count(*) FROM principal_role WHERE principal_id=$1),
			(SELECT count(*) FROM principal_role)`, id).Scan(
			&result.AssignedStudent, &result.AssignmentCount, &result.TotalAssignmentCount)
		return result, err
	}))
	defer control.Close()
	t16PublishReadyAndWait(t, ready, stop, control.URL)
}

func t16ProviderConfig(t *testing.T, databaseEnv, service string) (string, string, string, string, string) {
	t.Helper()
	dsn := os.Getenv(databaseEnv)
	u, err := url.Parse(dsn)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || !t16Loopback(u.Hostname()) {
		t.Fatalf("%s must be an explicit loopback PostgreSQL URL", databaseEnv)
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil || !t16Loopback(cfg.Host) || !strings.HasSuffix(cfg.Database, "_test") {
		t.Fatalf("%s must name an owned database ending in _test", databaseEnv)
	}
	for _, fallback := range cfg.Fallbacks {
		if !t16Loopback(fallback.Host) {
			t.Fatal("non-loopback PostgreSQL fallback is forbidden")
		}
	}
	if expected := os.Getenv("T16_POSTGRES_EXPECTED_SERVER_IP"); expected != "" && net.ParseIP(expected) == nil {
		t.Fatal("T16_POSTGRES_EXPECTED_SERVER_IP must be one exact root-attested IP address")
	}
	natsURL := os.Getenv("NATS_URL")
	nu, err := url.Parse(natsURL)
	if err != nil || nu.Scheme != "nats" || !t16Loopback(nu.Hostname()) || strings.Contains(natsURL, ",") {
		t.Fatal("NATS_URL must name one isolated loopback NATS server")
	}
	token := os.Getenv("T16_PROVIDER_TOKEN")
	if len(token) < 32 {
		t.Fatal("T16_PROVIDER_TOKEN must contain at least 32 bytes")
	}
	ready := os.Getenv("T16_" + service + "_READY_FILE")
	stop := os.Getenv("T16_" + service + "_STOP_FILE")
	if ready == "" {
		ready = os.Getenv("T16_READY_FILE")
	}
	if stop == "" {
		stop = os.Getenv("T16_STOP_FILE")
	}
	if !filepath.IsAbs(ready) || !filepath.IsAbs(stop) || ready == stop {
		t.Fatal("distinct absolute ready and stop file paths are required")
	}
	for _, path := range []string{ready, stop} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("provider ready/stop paths must not exist before startup")
		}
	}
	return dsn, natsURL, token, ready, stop
}

// The coordinator attests only its owned Docker backend's exact inspected IP.
// This does not relax the separate loopback-only client URL/fallback guards.
func t16ProviderStoreMatches(dsn, database, server, expectedServer string) bool {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil || !strings.HasSuffix(cfg.Database, "_test") || database != cfg.Database {
		return false
	}
	expected := net.ParseIP(expectedServer)
	if expectedServer != "" && expected == nil {
		return false
	}
	actual := net.ParseIP(server)
	return actual != nil && (actual.IsLoopback() || (expected != nil && actual.Equal(expected)))
}

func TestT16ProviderConnectedStoreGuard(t *testing.T) {
	const dsn = "postgres://test@127.0.0.1:5432/owned_t16_test"
	cases := []struct {
		name, database, server, expected string
		want                             bool
	}{
		{"native loopback", "owned_t16_test", "127.0.0.1", "", true},
		{"attested Docker backend", "owned_t16_test", "172.23.0.2", "172.23.0.2", true},
		{"unattested private backend", "owned_t16_test", "172.23.0.2", "", false},
		{"wrong attested backend", "owned_t16_test", "172.23.0.3", "172.23.0.2", false},
		{"wrong owned database", "different_test", "172.23.0.2", "172.23.0.2", false},
		{"invalid attestation", "owned_t16_test", "127.0.0.1", "172.23.0.0/24", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := t16ProviderStoreMatches(dsn, tc.database, tc.server, tc.expected); got != tc.want {
				t.Fatalf("connected-store guard returned %v, want %v", got, tc.want)
			}
		})
	}
}

func t16Loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func t16Subject(t *testing.T, env, fallback string) string {
	t.Helper()
	subject := os.Getenv(env)
	if subject == "" {
		subject = fallback
	}
	if strings.ContainsAny(subject, "*> \t\r\n") || strings.HasPrefix(subject, ".") || strings.HasSuffix(subject, ".") || strings.Contains(subject, "..") {
		t.Fatalf("%s must be a concrete NATS subject", env)
	}
	return subject
}

var t16PrincipalUUID = regexp.MustCompile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

func t16InspectHandler(token string, inspect func(context.Context, string) (any, error)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-T16-Provider-Token")), []byte(token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/inspect" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ids := r.URL.Query()["principal_id"]
		if len(ids) != 1 || !t16PrincipalUUID.MatchString(ids[0]) {
			http.Error(w, "one canonical principal UUID is required", http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		result, err := inspect(ctx, ids[0])
		if err != nil {
			http.Error(w, "inspection failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	})
}

func t16PublishReadyAndWait(t *testing.T, ready, stop, controlURL string) {
	t.Helper()
	file, err := os.OpenFile(ready, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("cannot exclusively create provider ready file")
	}
	err = json.NewEncoder(file).Encode(map[string]string{
		"control_url":    controlURL,
		"classification": "actual-provider",
	})
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		t.Fatal("cannot write provider readiness")
	}
	timer := time.NewTimer(20 * time.Minute)
	defer timer.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-timer.C:
			t.Fatal("provider coordinator did not stop harness within 20 minutes")
		case <-ticker.C:
			if info, err := os.Lstat(stop); err == nil {
				if !info.Mode().IsRegular() {
					t.Fatal("provider stop path must be a regular file")
				}
				return
			} else if !os.IsNotExist(err) {
				t.Fatal("cannot inspect provider stop file")
			}
		}
	}
}
