package config

import (
	"errors"
	"os"
)

// MentorOwnerConfig is disabled unless its explicit opt-in is true. It is
// separate from the legacy broker and JWT/reviewer configuration.
type MentorOwnerConfig struct {
	Enabled                    bool
	NATSURL                    string
	NATSCredentialsFile        string
	NATSCAFile                 string
	AuthAdminLookupPublicKey   string
	AuthRoleDecisionPublicKey  string
	ReadbackRequestPublicKey   string
	AdminDecisionPrivateKey    string
	AdminDecisionPublicKey     string
	ReadbackDecisionPrivateKey string
	ReadbackDecisionPublicKey  string
}

func loadMentorOwner() (MentorOwnerConfig, error) {
	switch os.Getenv("RBAC_MENTOR_OWNER_ENABLED") {
	case "", "false":
		return MentorOwnerConfig{}, nil
	case "true":
		return MentorOwnerConfig{
			Enabled:                    true,
			NATSURL:                    os.Getenv("RBAC_MENTOR_NATS_URL"),
			NATSCredentialsFile:        os.Getenv("RBAC_MENTOR_NATS_CREDENTIALS_FILE"),
			NATSCAFile:                 os.Getenv("RBAC_MENTOR_NATS_CA_FILE"),
			AuthAdminLookupPublicKey:   os.Getenv("RBAC_MENTOR_AUTH_ADMIN_LOOKUP_PUBLIC_KEY"),
			AuthRoleDecisionPublicKey:  os.Getenv("RBAC_MENTOR_AUTH_ROLE_DECISION_PUBLIC_KEY"),
			ReadbackRequestPublicKey:   os.Getenv("RBAC_MENTOR_READBACK_REQUEST_PUBLIC_KEY"),
			AdminDecisionPrivateKey:    os.Getenv("RBAC_MENTOR_ADMIN_DECISION_PRIVATE_KEY"),
			AdminDecisionPublicKey:     os.Getenv("RBAC_MENTOR_ADMIN_DECISION_PUBLIC_KEY"),
			ReadbackDecisionPrivateKey: os.Getenv("RBAC_MENTOR_READBACK_DECISION_PRIVATE_KEY"),
			ReadbackDecisionPublicKey:  os.Getenv("RBAC_MENTOR_READBACK_DECISION_PUBLIC_KEY"),
		}, nil
	default:
		return MentorOwnerConfig{}, errors.New("RBAC_MENTOR_OWNER_ENABLED must be exactly true or false")
	}
}
