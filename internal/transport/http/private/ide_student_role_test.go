package private

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type ideStudentRoleStub struct {
	role string
	calls int
}

func (s *ideStudentRoleStub) GetDefaultRole(_ context.Context, _ string) (string, error) {
	s.calls++
	return s.role, nil
}

func TestIDEStudentRolePrivateReadIsDefaultOffAndCapabilityFenced(t *testing.T) {
	const studentID = "11111111-1111-4111-8111-111111111111"
	const path = "/ide/v1/principals/" + studentID + "/student-role"
	token := strings.Repeat("r", 48)
	repo := &ideStudentRoleStub{role:"student"}
	run := func(h *IDEStudentRoleHandler, service, credential, roleHeader string, extra func(*http.Request)) *httptest.ResponseRecorder {
		mux := http.NewServeMux()
		RegisterIDEStudentRoleRoutes(mux, h)
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if service != "" { req.Header.Set("X-Service-Name", service) }
		if credential != "" { req.Header.Set("X-Internal-Token", credential) }
		if roleHeader != "" { req.Header.Set("X-User-Role", roleHeader) }
		if extra != nil { extra(req) }
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	disabled := run(&IDEStudentRoleHandler{Token:token, Roles:repo}, "ms-go-practice-runtime", token, "", nil)
	if disabled.Code != http.StatusNotFound || repo.calls != 0 {
		t.Fatalf("off route: status=%d calls=%d", disabled.Code, repo.calls)
	}
	h := &IDEStudentRoleHandler{Enabled:true, Token:token, Roles:repo}
	for _, tc := range []struct {
		name, service, token, role string
		extra func(*http.Request)
	}{
		{"missing token", "ms-go-practice-runtime", "", "", nil},
		{"wrong token", "ms-go-practice-runtime", strings.Repeat("w", 48), "", nil},
		{"foreign caller", "ms-go-course", token, "", nil},
		{"missing service", "", token, "", nil},
		{"caller role assertion", "ms-go-practice-runtime", token, "ADMIN", nil},
		{"duplicate token", "ms-go-practice-runtime", token, "", func(r *http.Request){ r.Header.Add("X-Internal-Token", token) }},
		{"duplicate service", "ms-go-practice-runtime", token, "", func(r *http.Request){ r.Header.Add("X-Service-Name", "ms-go-practice-runtime") }},
		{"browser bearer", "ms-go-practice-runtime", token, "", func(r *http.Request){ r.Header.Set("Authorization", "Bearer attacker") }},
		{"browser cookie", "ms-go-practice-runtime", token, "", func(r *http.Request){ r.Header.Set("Cookie", "sid=attacker") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := run(h, tc.service, tc.token, tc.role, tc.extra)
			if rec.Code != http.StatusForbidden || repo.calls != 0 {
				t.Fatalf("denial: status=%d calls=%d", rec.Code, repo.calls)
			}
		})
	}
	rec := run(h, "ms-go-practice-runtime", token, "", nil)
	if rec.Code != http.StatusOK || repo.calls != 1 ||
		!strings.Contains(rec.Body.String(), `"role":"STUDENT"`) ||
		!strings.Contains(rec.Body.String(), `"student_id":"`+studentID+`"`) ||
		!strings.Contains(rec.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("trusted read: status=%d calls=%d body=%s", rec.Code, repo.calls, rec.Body.String())
	}
}

func TestIDEStudentRolePrivateReadRejectsNonStudentAndInvalidConfiguration(t *testing.T) {
	const path = "/ide/v1/principals/11111111-1111-4111-8111-111111111111/student-role"
	repo := &ideStudentRoleStub{role:"admin"}
	for _, token := range []string{"", "short", "change-me"+strings.Repeat("x",48)} {
		mux := http.NewServeMux()
		RegisterIDEStudentRoleRoutes(mux, &IDEStudentRoleHandler{Enabled:true, Token:token, Roles:repo})
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusNotFound { t.Fatalf("invalid config mounted route: %d", rec.Code) }
	}
	token := strings.Repeat("r",48)
	mux := http.NewServeMux()
	RegisterIDEStudentRoleRoutes(mux, &IDEStudentRoleHandler{Enabled:true, Token:token, Roles:repo})
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("X-Internal-Token", token)
	req.Header.Set("X-Service-Name", "ms-go-practice-runtime")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "admin") {
		t.Fatalf("nonstudent role leaked: %d %s", rec.Code, rec.Body.String())
	}
}
