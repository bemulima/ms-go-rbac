package config

import (
	"strings"
	"testing"
)

func TestIDEStudentRoleReadIsDefaultOffAndRequiresDedicatedToken(t *testing.T) {
	t.Setenv("RBAC_IDE_STUDENT_ROLE_ENABLED", "false")
	t.Setenv("RBAC_IDE_STUDENT_ROLE_TOKEN", "")
	cfg, err := Load()
	if err != nil || cfg.IDEStudentRoleEnabled || cfg.IDEStudentRoleToken != "" {
		t.Fatalf("default-off role read: %#v %v", cfg, err)
	}
	t.Setenv("RBAC_IDE_STUDENT_ROLE_ENABLED", "true")
	if _, err := Load(); err == nil {
		t.Fatal("enabled role endpoint without credential accepted")
	}
	token := strings.Repeat("r", 48)
	t.Setenv("RBAC_IDE_STUDENT_ROLE_TOKEN", token)
	cfg, err = Load()
	if err != nil || !cfg.IDEStudentRoleEnabled || cfg.IDEStudentRoleToken != token {
		t.Fatalf("valid role read configuration rejected: %#v %v", cfg, err)
	}
	for _, bad := range []string{"short", strings.Repeat("x", 31), "change-me" + strings.Repeat("x", 40), strings.Repeat("x", 48) + " "} {
		t.Setenv("RBAC_IDE_STUDENT_ROLE_TOKEN", bad)
		if _, err := Load(); err == nil {
			t.Fatalf("bad role read credential accepted (len=%d)", len(bad))
		}
	}
}
