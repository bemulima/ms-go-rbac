package config

import (
	"strings"
	"testing"
)

// MENT-27, IDE-28 and MCP-53 are independently configured owner capabilities.
func TestMentorOwnerIDEAndMCPStudentRoleConfigurationCoexist(t *testing.T) {
	t.Setenv("RBAC_MENTOR_OWNER_ENABLED", "true")
	t.Setenv("RBAC_MENTOR_NATS_URL", "tls://mentor-broker.invalid:4222")
	t.Setenv("RBAC_MENTOR_NATS_CREDENTIALS_FILE", "/operator/mentor.creds")
	t.Setenv("RBAC_MENTOR_NATS_CA_FILE", "/operator/mentor-ca.pem")
	for name, value := range map[string]string{
		"AUTH_ADMIN_LOOKUP_PUBLIC_KEY":  "lookup",
		"AUTH_ROLE_DECISION_PUBLIC_KEY": "decision",
		"READBACK_REQUEST_PUBLIC_KEY":   "request",
		"ADMIN_DECISION_PRIVATE_KEY":    "admin-private",
		"ADMIN_DECISION_PUBLIC_KEY":     "admin-public",
		"READBACK_DECISION_PRIVATE_KEY": "readback-private",
		"READBACK_DECISION_PUBLIC_KEY":  "readback-public",
	} {
		t.Setenv("RBAC_MENTOR_"+name, value)
	}

	ideToken := strings.Repeat("i", 48)
	t.Setenv("RBAC_IDE_STUDENT_ROLE_ENABLED", "true")
	t.Setenv("RBAC_IDE_STUDENT_ROLE_TOKEN", ideToken)
	t.Setenv("MCP_STUDENT_RBAC_ENABLED", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("independent Mentor and IDE role-reader opt-ins rejected: %v", err)
	}
	if !cfg.MentorOwner.Enabled || !cfg.IDEStudentRoleEnabled || cfg.IDEStudentRoleToken != ideToken || cfg.MCPStudentRBACEnabled {
		t.Fatalf("one owner capability was lost: mentor=%t ide=%t token_match=%t",
			cfg.MentorOwner.Enabled, cfg.IDEStudentRoleEnabled, cfg.IDEStudentRoleToken == ideToken)
	}
	if cfg.MentorOwner.NATSCredentialsFile != "/operator/mentor.creds" || cfg.MentorOwner.NATSCAFile != "/operator/mentor-ca.pem" {
		t.Fatal("Mentor owner adopted an unrelated IDE credential")
	}

	t.Setenv("MCP_STUDENT_RBAC_ENABLED", "true")
	cfg, err = Load()
	if err != nil || !cfg.MentorOwner.Enabled || !cfg.IDEStudentRoleEnabled || !cfg.MCPStudentRBACEnabled {
		t.Fatal("explicit MCP opt-in must coexist with Mentor and IDE")
	}

	t.Setenv("RBAC_IDE_STUDENT_ROLE_TOKEN", "placeholder"+strings.Repeat("x", 48))
	if _, err := Load(); err == nil {
		t.Fatal("Mentor owner opt-in bypassed the IDE token validator")
	}

	t.Setenv("RBAC_IDE_STUDENT_ROLE_ENABLED", "false")
	t.Setenv("RBAC_IDE_STUDENT_ROLE_TOKEN", "")
	cfg, err = Load()
	if err != nil || !cfg.MentorOwner.Enabled || cfg.IDEStudentRoleEnabled || cfg.IDEStudentRoleToken != "" || !cfg.MCPStudentRBACEnabled {
		t.Fatalf("disabling IDE must leave Mentor opt-in intact: mentor=%t ide=%t err=%v",
			cfg.MentorOwner.Enabled, cfg.IDEStudentRoleEnabled, err)
	}
}
