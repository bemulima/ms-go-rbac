package nats

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/example/ms-rbac-service/internal/domain"
)

const cat49CatalogStudentID = "11111111-1111-4111-8111-111111111111"

type cat49CatalogDefaultRoleReader struct {
	defaultRole      string
	foreignScopeRole string
	err              error
	calls            int
	seenID           string
}

func (r *cat49CatalogDefaultRoleReader) GetDefaultRole(_ context.Context, id string) (string, error) {
	r.calls++
	r.seenID = id
	return r.defaultRole, r.err
}

func cat49CatalogRoleRequest() []byte {
	return []byte(fmt.Sprintf(`{"user_id":%q}`, cat49CatalogStudentID))
}

func TestCAT49CatalogDefaultRoleReadUsesOnlyExactGlobalScope(t *testing.T) {
	for _, tc := range []struct {
		name             string
		defaultRole      string
		foreignScopeRole string
		wantOK           bool
		wantRole         string
	}{
		{"student", "student", "admin", true, "student"},
		{"student-pro", "student_pro", "guest", true, "student_pro"},
		{"foreign-scope-only", "", "student", false, ""},
		{"admin", "admin", "student", false, ""},
		{"guest", "guest", "student_pro", false, ""},
		{"wrong-case", "STUDENT", "", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader := &cat49CatalogDefaultRoleReader{defaultRole: tc.defaultRole, foreignScopeRole: tc.foreignScopeRole}
			got := (DefaultStudentRoleChecker{Roles: reader}).handle(context.Background(), cat49CatalogRoleRequest())
			if got.OK != tc.wantOK || got.Role != tc.wantRole || got.Error != "" || reader.calls != 1 || reader.seenID != cat49CatalogStudentID {
				t.Fatalf("incorrect default-scope decision: %+v, reader: %+v", got, reader)
			}
		})
	}
}

func TestCAT49CatalogDefaultRoleReadRejectsUntrustedRequest(t *testing.T) {
	reader := &cat49CatalogDefaultRoleReader{defaultRole: "student"}
	checker := DefaultStudentRoleChecker{Roles: reader}
	for _, body := range [][]byte{
		nil,
		[]byte(`{}`),
		[]byte(`[]`),
		[]byte(`{"user_id":"00000000-0000-0000-0000-000000000000"}`),
		[]byte(`{"user_id":"invalid"}`),
		[]byte(`{"user_id":"11111111-1111-4111-8111-111111111111","role":"student"}`),
		[]byte(`{"user_id":"11111111-1111-4111-8111-111111111111","user_id":"11111111-1111-4111-8111-111111111111"}`),
		[]byte(`{"user_id":"11111111-1111-4111-8111-111111111111"}{"user_id":"11111111-1111-4111-8111-111111111111"}`),
		[]byte(`{"user_id":"AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"}`),
		[]byte(`{"user_id":null}`),
		[]byte(`{"user_id":123}`),
		[]byte(strings.Repeat("x", maxDefaultStudentRolePayload+1)),
	} {
		got := checker.handle(context.Background(), body)
		if got.OK || got.Role != "" || got.Error != "invalid_payload" || reader.calls != 0 {
			t.Fatalf("malformed or forged request admitted: %+v (%d calls)", got, reader.calls)
		}
	}
}

func TestCAT49CatalogDefaultRoleReadFailsClosed(t *testing.T) {
	for _, cause := range []error{errors.New("sensitive SQL details"), domain.ErrAmbiguousPrincipalRole, context.Canceled} {
		reader := &cat49CatalogDefaultRoleReader{defaultRole: "student", err: cause}
		got := (DefaultStudentRoleChecker{Roles: reader}).handle(context.Background(), cat49CatalogRoleRequest())
		if got.OK || got.Role != "" || got.Error != "role_check_unavailable" || strings.Contains(got.Error, "SQL") || reader.calls != 1 {
			t.Fatalf("role reader failure leaked or authorized: %+v", got)
		}
	}
	if got := (DefaultStudentRoleChecker{}).handle(context.Background(), cat49CatalogRoleRequest()); got.OK || got.Error != "role_check_unavailable" {
		t.Fatalf("missing reader admitted: %+v", got)
	}
	if err := (DefaultStudentRoleChecker{}).Listen(); err == nil {
		t.Fatal("missing broker and reader must deny subscription")
	}
}
