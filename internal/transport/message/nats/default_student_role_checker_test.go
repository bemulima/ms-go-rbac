package nats

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/example/ms-rbac-service/internal/domain"
)

const cat02GlobalActorID = "11111111-1111-4111-8111-111111111111"

type cat02DefaultStudentRoleFixture struct {
	defaultRole string
	scopedOnlyRole string
	err error
	calls int
	subject string
}

func (reader *cat02DefaultStudentRoleFixture) GetDefaultRole(
	_ context.Context, principalID string,
) (string, error) {
	reader.calls++
	reader.subject = principalID
	return reader.defaultRole, reader.err
}

func cat02DefaultStudentRequest() []byte {
	return []byte(fmt.Sprintf(`{"user_id":%q}`, cat02GlobalActorID))
}

func TestCAT02DefaultStudentCheckerUsesCanonicalGlobalRoleOnly(t *testing.T) {
	for _, test := range []struct {
		name string
		global string
		otherScope string
		allowed bool
		expectedRole string
	}{
		{"global-student", "student", "admin", true, "student"},
		{"global-student-pro", "student_pro", "guest", true, "student_pro"},
		{"only-foreign-scoped-student", "", "student", false, ""},
		{"global-admin-and-foreign-student", "admin", "student", false, ""},
		{"global-guest-and-foreign-student-pro", "guest", "student_pro", false, ""},
		{"global-unsupported-casing", "STUDENT", "", false, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := &cat02DefaultStudentRoleFixture{
				defaultRole: test.global, scopedOnlyRole: test.otherScope,
			}
			checker := DefaultStudentRoleChecker{Roles: reader}
			response := checker.handle(context.Background(), cat02DefaultStudentRequest())
			if response.OK != test.allowed || response.Role != test.expectedRole ||
				response.Error != "" || reader.calls != 1 || reader.subject != cat02GlobalActorID {
				t.Fatalf("unexpected default-scope result: %+v reader=%+v", response, reader)
			}
		})
	}
}

func TestCAT02DefaultStudentCheckerRejectsUntrustedPayload(t *testing.T) {
	reader := &cat02DefaultStudentRoleFixture{defaultRole: "student"}
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
		[]byte(strings.Repeat("X", maxDefaultStudentRolePayload+1)),
	} {
		response := checker.handle(context.Background(), body)
		if response.OK || response.Role != "" || response.Error != "invalid_payload" || reader.calls != 0 {
			t.Fatalf("untrusted request reached authority: %+v calls=%d", response, reader.calls)
		}
	}
}

func TestCAT02DefaultStudentCheckerFailsClosedOnMissingOrAmbiguousRole(t *testing.T) {
	for _, failure := range []error{
		errors.New("private SQL connection details"),
		domain.ErrAmbiguousPrincipalRole,
		context.Canceled,
	} {
		reader := &cat02DefaultStudentRoleFixture{defaultRole: "student", err: failure}
		response := (DefaultStudentRoleChecker{Roles: reader}).handle(
			context.Background(), cat02DefaultStudentRequest())
		if response.OK || response.Role != "" || response.Error != "role_check_unavailable" ||
			strings.Contains(response.Error, "SQL") || reader.calls != 1 {
			t.Fatalf("backend failure exposed or granted role: %+v", response)
		}
	}
	response := (DefaultStudentRoleChecker{}).handle(context.Background(), cat02DefaultStudentRequest())
	if response.OK || response.Error != "role_check_unavailable" {
		t.Fatalf("nil reader granted role: %+v", response)
	}
	if err := (DefaultStudentRoleChecker{}).Listen(); err == nil {
		t.Fatal("missing broker and reader must fail subscription")
	}
}
