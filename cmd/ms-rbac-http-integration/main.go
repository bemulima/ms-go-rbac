// Command ms-rbac-http-integration owns one disposable HTTP fixture database.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 25*time.Minute)
	defer cancel()
	parent := os.Getppid()
	// The policy runner signals the outer go-run process. Detect reparenting
	// when that wrapper exits so this adapter can still clean its own database.
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if os.Getppid() != parent {
					cancel()
					return
				}
			}
		}
	}()
	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func loopback(host string) bool {
	return host == "localhost" || (net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback())
}

func run(ctx context.Context) (result error) {
	if os.Getenv("RBAC_MIGRATION_TEST_ALLOW_CREATE_DATABASE") != "YES" {
		return errors.New("RBAC_MIGRATION_TEST_ALLOW_CREATE_DATABASE=YES is required for a disposable PostgreSQL server")
	}
	dsn := os.Getenv("RBAC_MIGRATION_TEST_ADMIN_DSN")
	u, err := url.Parse(dsn)
	if err != nil || dsn == "" || (u.Scheme != "postgres" && u.Scheme != "postgresql") || !loopback(u.Hostname()) || u.Path != "/postgres" || u.User == nil || u.User.Username() == "" || u.Fragment != "" {
		return errors.New("RBAC_MIGRATION_TEST_ADMIN_DSN must explicitly name a loopback PostgreSQL postgres database and user")
	}
	// Endpoint/user/database overrides and service files are not fixture inputs.
	for key, values := range u.Query() {
		if key != "sslmode" || len(values) != 1 {
			return errors.New("the disposable admin URL permits only the sslmode query parameter")
		}
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		return errors.New("invalid disposable PostgreSQL admin configuration")
	}
	if !loopback(config.Host) || config.Database != "postgres" {
		return errors.New("nonloopback or nonpostgres admin configuration is forbidden")
	}
	for _, fallback := range config.Fallbacks {
		if !loopback(fallback.Host) {
			return errors.New("nonloopback PostgreSQL fallback is forbidden")
		}
	}
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return errors.New("cannot connect to disposable PostgreSQL admin database")
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := admin.Close(closeCtx); err != nil {
			result = errors.Join(result, errors.New("cannot close disposable PostgreSQL admin connection"))
		}
	}()
	var database, user string
	var superuser bool
	if err := admin.QueryRow(ctx, `SELECT current_database(), current_user, r.rolsuper FROM pg_roles r WHERE r.rolname = current_user`).Scan(&database, &user, &superuser); err != nil || database != "postgres" || user != config.User || !superuser {
		return errors.New("disposable PostgreSQL identity must be the explicit postgres database superuser")
	}
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return errors.New("cannot generate disposable database identity")
	}
	name := "rbac_http_test_" + hex.EncodeToString(random[:])
	identifier := pgx.Identifier{name}.Sanitize()
	// An interrupted CREATE can have an ambiguous outcome. Never drop a database
	// unless this invocation received confirmation that it created that exact name.
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+identifier); err != nil {
		return errors.New("cannot confirm disposable HTTP database creation")
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cleanup, err := pgx.ConnectConfig(cleanupCtx, config)
		if err != nil {
			result = errors.Join(result, fmt.Errorf("cannot reconnect to clean owned HTTP database %s", name))
			return
		}
		defer func() {
			if err := cleanup.Close(cleanupCtx); err != nil {
				result = errors.Join(result, errors.New("cannot close disposable PostgreSQL cleanup connection"))
			}
		}()
		if _, err := cleanup.Exec(cleanupCtx, "DROP DATABASE "+identifier+" WITH (FORCE)"); err != nil {
			result = errors.Join(result, fmt.Errorf("cannot clean owned HTTP database %s", name))
		}
	}()
	u.Path = "/" + name
	env := make([]string, 0, len(os.Environ())+1)
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "DB_DSN=") {
			env = append(env, value)
		}
	}
	env = append(env, "DB_DSN="+u.String())
	if err := command(ctx, env, "run", "./cmd/ms-rbac-migrate", "up"); err != nil {
		return errors.New("HTTP fixture schema migration failed")
	}
	if err := command(ctx, env, "test", "-tags=integration", "./test/integration", "-count=1"); err != nil {
		return errors.New("HTTP integration suite failed")
	}
	return nil
}

func command(ctx context.Context, env []string, args ...string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	cmd := exec.Command("go", args...)
	cmd.Env = env
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		// Go launches migration/test binaries. Stop the complete child group and
		// reap it before the caller's database cleanup can run.
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		select {
		case <-done:
		case <-timer.C:
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			<-done
		}
		// The Go leader can exit while a test descendant survives SIGTERM.
		// Terminate any remaining members before database cleanup begins.
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		return ctx.Err()
	}
}
