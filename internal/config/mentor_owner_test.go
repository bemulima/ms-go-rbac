package config

import "testing"

func TestMentorOwnerConfigExplicitOptIn(t *testing.T) {
	for _, value := range []string{"", "false", "true", "FALSE", "TRUE", "1", "0", "yes", " false", "true ", "garbage"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("RBAC_MENTOR_OWNER_ENABLED", value)
			t.Setenv("RBAC_MENTOR_NATS_URL", "tls://mentor-broker.invalid:4222")
			t.Setenv("RBAC_MENTOR_NATS_CREDENTIALS_FILE", "/operator/mentor.creds")
			t.Setenv("RBAC_MENTOR_NATS_CA_FILE", "/operator/ca.pem")
			fields := map[string]string{
				"AUTH_ADMIN_LOOKUP_PUBLIC_KEY": "lookup", "AUTH_ROLE_DECISION_PUBLIC_KEY": "decision",
				"READBACK_REQUEST_PUBLIC_KEY": "request", "ADMIN_DECISION_PRIVATE_KEY": "admin-private",
				"ADMIN_DECISION_PUBLIC_KEY": "admin-public", "READBACK_DECISION_PRIVATE_KEY": "readback-private",
				"READBACK_DECISION_PUBLIC_KEY": "readback-public",
			}
			for name, value := range fields {
				t.Setenv("RBAC_MENTOR_"+name, value)
			}
			cfg, err := Load()
			if value != "" && value != "false" && value != "true" {
				if err == nil {
					t.Fatal("ambiguous opt-in must reject configuration")
				}
				return
			}
			if err != nil {
				t.Fatal("valid explicit opt-in failed")
			}
			if value != "true" {
				if cfg.MentorOwner != (MentorOwnerConfig{}) {
					t.Fatal("disabled feature must not load its configuration")
				}
				return
			}
			want := MentorOwnerConfig{Enabled: true, NATSURL: "tls://mentor-broker.invalid:4222",
				NATSCredentialsFile: "/operator/mentor.creds", NATSCAFile: "/operator/ca.pem",
				AuthAdminLookupPublicKey: "lookup", AuthRoleDecisionPublicKey: "decision", ReadbackRequestPublicKey: "request",
				AdminDecisionPrivateKey: "admin-private", AdminDecisionPublicKey: "admin-public",
				ReadbackDecisionPrivateKey: "readback-private", ReadbackDecisionPublicKey: "readback-public"}
			if cfg.MentorOwner != want {
				t.Fatal("enabled configuration did not map dedicated settings exactly")
			}
		})
	}
}
