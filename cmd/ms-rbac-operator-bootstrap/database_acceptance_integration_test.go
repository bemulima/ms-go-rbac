//go:build integration

package main

import (
	"bytes"
	"context"
	"net"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestOperatorCLILiveIsolatedDatabaseGuards(t *testing.T) {
	dsn := os.Getenv("RBAC_SIGNUP_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires explicitly owned isolated SQL acceptance DB")
	}
	u, err := url.Parse(dsn)
	if err != nil || !strings.HasSuffix(u.Path, "_test") || u.Port() != "5432" || (u.Hostname() != "localhost" && !net.ParseIP(u.Hostname()).IsLoopback()) {
		t.Fatal("isolated loopback *_test:5432 target required")
	}
	ctx := context.Background()
	user := u.User.Username()
	database := strings.TrimPrefix(u.Path, "/")
	// Exercise the published real database opener with exact test identity only.
	service, close, err := openDatabase(ctx, dsn, database, user)
	if err != nil || service == nil {
		t.Fatal("expected isolated non-superuser identity unavailable")
	}
	close()
	for _, test := range []struct{ database, user string }{{"lw_rbac", user}, {database, "wrong-operator-user"}} {
		_, close, err := openDatabase(ctx, dsn, test.database, test.user)
		if close != nil {
			close()
		}
		if err == nil {
			t.Fatal("mismatched actual database/user accepted")
		}
	}
	bad := *u
	bad.Host = net.JoinHostPort(u.Hostname(), "5433")
	if _, _, err := openDatabase(ctx, bad.String(), database, user); err == nil {
		t.Fatal("nonallowlisted port accepted")
	}
	bad = *u
	bad.User = url.UserPassword(user, "not-the-private-test-password")
	if _, close, err := openDatabase(ctx, bad.String(), database, user); err == nil {
		if close != nil {
			close()
		}
		t.Fatal("invalid database credentials accepted")
	}
	// Full CLI must refuse this _test DB: it never relaxes its lw_rbac guard.
	env := func(key string) string {
		return map[string]string{"APP_ENV": "local-operator", "RBAC_OPERATOR_BOOTSTRAP": "enabled", "RBAC_OPERATOR_ENVIRONMENT": "learning-workspace-local", "DB_DSN": dsn}[key]
	}
	var output bytes.Buffer
	if run(goodArgs, env, &output, openDatabase) == nil || output.Len() != 0 {
		t.Fatal("production CLI database guard bypassed or produced receipt")
	}
}
