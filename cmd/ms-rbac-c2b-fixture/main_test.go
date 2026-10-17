package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/example/ms-rbac-service/internal/domain"
	"github.com/example/ms-rbac-service/internal/infrastructure/c2bfixture"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixtureEnvironment(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(key, "PG") {
			t.Setenv(key, "")
			os.Unsetenv(key)
		}
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("test key generation failed")
	}
	m := c2bfixture.Marker{Schema: "c2b-proof-ownership.v1", Project: "c2b-proof-20261016", Run: domain.C2BRun, AuthDB: "c2b_auth_20261016", RBACDB: "c2b_rbac_20261016", PublicKey: base64.StdEncoding.EncodeToString(pub), Instance: domain.C2BInstance, Submission: domain.C2BSubmission, Expires: time.Now().Add(time.Hour)}
	raw, _ := json.Marshal(m)
	path := filepath.Join(t.TempDir(), "owner.json")
	if os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("test marker write failed")
	}
	t.Setenv("C2B_OWNERSHIP_MARKER", path)
	t.Setenv("C2B_ENV", "c2b-proof")
	t.Setenv("C2B_FIXTURE_ENABLED", "true")
	t.Setenv("APP_ENV", "c2b-proof")
	return priv
}
func fixtureDSN() string {
	return "postgres://c2b_rbac_fixture:test-only-password@127.0.0.1:49920/c2b_rbac_20261016?sslmode=disable"
}
func deniedDSNs() map[string]string {
	base := fixtureDSN()
	return map[string]string{
		"host":             base + "&host=203.0.113.1",
		"port":             base + "&port=5432",
		"user":             base + "&user=postgres",
		"dbname":           base + "&dbname=other",
		"database":         base + "&database=other",
		"hostaddr":         base + "&hostaddr=203.0.113.1",
		"service":          base + "&service=other",
		"servicefile":      base + "&servicefile=/tmp/unowned",
		"duplicate":        base + "&sslmode=disable",
		"encoded_key":      base + "&%68ost=203.0.113.1",
		"encoded_option":   strings.Replace(base, "sslmode=disable", "sslmode=%64isable", 1),
		"encoded_path":     strings.Replace(base, "/c2b_", "/%632b_", 1),
		"encoded_user":     strings.Replace(base, "postgres://c2b_", "postgres://%632b_", 1),
		"remote_fallback":  strings.Replace(base, "127.0.0.1:49920", "127.0.0.1:49920,203.0.113.1:49920", 1),
		"wrong_port":       strings.Replace(base, ":49920", ":5432", 1),
		"remote":           strings.Replace(base, "127.0.0.1", "203.0.113.1", 1),
		"localhost_alias":  strings.Replace(base, "127.0.0.1", "localhost", 1),
		"database_path":    strings.Replace(base, "/c2b_rbac_20261016", "/other", 1),
		"user_authority":   strings.Replace(base, "c2b_rbac_fixture:", "postgres:", 1),
		"options":          base + "&options=-csearch_path%3Dpublic",
		"unexpected":       base + "&application_name=other",
		"empty_query_pair": base + "&",
		"fragment":         base + "#other",
		"missing_password": strings.Replace(base, ":test-only-password@", "@", 1),
		"empty_password":   strings.Replace(base, "test-only-password", "", 1),
		"prefer_tls":       strings.Replace(base, "sslmode=disable", "sslmode=prefer", 1),
	}
}

func TestDeniedConnectionNeverReachesDatabaseOpener(t *testing.T) {
	key := fixtureEnvironment(t)
	intent, err := domain.C2BActor("mentor")
	if err != nil {
		t.Fatal("test intent unavailable")
	}
	raw, err := json.Marshal(intent)
	if err != nil {
		t.Fatal("test intent encoding failed")
	}
	signed := domain.C2BSignedIntent{Schema: "c2b-signed-bootstrap.v1", Payload: base64.StdEncoding.EncodeToString(raw), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, raw))}
	input, err := json.Marshal(signed)
	if err != nil {
		t.Fatal("test envelope encoding failed")
	}
	// Positive control proves valid input reaches the opener, so a denial test
	// cannot pass merely because later signature/input validation fails.
	t.Setenv("C2B_FIXTURE_DSN", fixtureDSN())
	controlCalls := 0
	control := func(context.Context, *pgxpool.Config) (*pgxpool.Pool, error) {
		controlCalls++
		return nil, errors.New("test opener stop")
	}
	if runWithPool([]string{"apply"}, strings.NewReader(string(input)), io.Discard, control) == nil || controlCalls != 1 {
		t.Fatal("valid entrypoint failed before opener")
	}
	check := func(t *testing.T, dsn string) {
		t.Helper()
		t.Setenv("C2B_FIXTURE_DSN", dsn)
		calls := 0
		open := func(context.Context, *pgxpool.Config) (*pgxpool.Pool, error) {
			calls++
			return nil, errors.New("unexpected pool open")
		}
		err := runWithPool([]string{"apply"}, strings.NewReader(string(input)), io.Discard, open)
		if err == nil || calls != 0 {
			t.Fatal("denied configuration reached connection attempt")
		}
		if strings.Contains(err.Error(), "test-only-password") {
			t.Fatal("credential-bearing error")
		}
	}
	for name, dsn := range deniedDSNs() {
		t.Run(name, func(t *testing.T) { check(t, dsn) })
	}
	for _, key := range []string{"PGHOST", "PGSERVICE", "PGSERVICEFILE", "PGPASSFILE", "PGOPTIONS", "PGPORT", "PGUSER", "PGDATABASE", "PGHOSTADDR"} {
		t.Run(key, func(t *testing.T) { t.Setenv(key, "unowned"); check(t, fixtureDSN()) })
	}
	t.Run("production", func(t *testing.T) { t.Setenv("APP_ENV", "production"); check(t, fixtureDSN()) })
}

// An in-memory PostgreSQL wire fixture checks the real connector path without
// a socket listener, preserved database, provisioning write or service process.
func TestValidatedConfigurationReachesConnectorUnchanged(t *testing.T) {
	fixtureEnvironment(t)
	_, config, err := c2bfixture.PrepareConnection("rbac", fixtureDSN())
	if err != nil {
		t.Fatal("valid fixture rejected")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	calls := 0
	wireResult := make(chan bool, 1)
	config.ConnConfig.DialFunc = func(_ context.Context, network, address string) (net.Conn, error) {
		calls++
		if network != "tcp" || address != "127.0.0.1:49920" {
			return nil, errors.New("unexpected destination")
		}
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			_ = server.SetDeadline(time.Now().Add(3 * time.Second))
			backend := pgproto3.NewBackend(server, server)
			message, e := backend.ReceiveStartupMessage()
			if e != nil {
				wireResult <- false
				return
			}
			startup, ok := message.(*pgproto3.StartupMessage)
			wireResult <- ok && startup.Parameters["user"] == "c2b_rbac_fixture" && startup.Parameters["database"] == "c2b_rbac_20261016"
			if !ok {
				return
			}
			backend.Send(&pgproto3.AuthenticationOk{})
			backend.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "15.0"})
			backend.Send(&pgproto3.ParameterStatus{Name: "client_encoding", Value: "UTF8"})
			backend.Send(&pgproto3.BackendKeyData{ProcessID: 1, SecretKey: 1})
			backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			if backend.Flush() != nil {
				return
			}
			for {
				message, e := backend.Receive()
				if e != nil {
					return
				}
				switch message.(type) {
				case *pgproto3.Terminate:
					return
				case *pgproto3.Query:
					backend.Send(&pgproto3.EmptyQueryResponse{})
					backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
					if backend.Flush() != nil {
						return
					}
				default:
					return
				}
			}
		}()
		return client, nil
	}
	// A later environment change must not reparse or redirect the approved object.
	t.Setenv("PGHOST", "203.0.113.1")
	t.Setenv("PGSERVICE", "unowned")
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal("validated pool construction failed")
	}
	defer pool.Close()
	if err = pool.Ping(ctx); err != nil {
		t.Fatal("validated pool ping failed")
	}
	if calls != 1 {
		t.Fatal("connector did not consume the approved config")
	}
	select {
	case ok := <-wireResult:
		if !ok {
			t.Fatal("effective startup identity changed")
		}
	case <-ctx.Done():
		t.Fatal("wire fixture timed out")
	}
}
