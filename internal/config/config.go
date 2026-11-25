package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds environment driven settings for the service.
type Config struct {
	AppEnv                               string
	HTTPAddr                             string
	DBDSN                                string
	NATSURL                              string
	AuthSignupPublicKey                  string
	AuthJWTPublicKey                     string
	AuthJWTIssuer                        string
	ReviewerPermissionDecisionPrivateKey string
	MCPStudentRBACEnabled                bool
	MCPStudentRoleDecisionPrivateKey     string
	MCPStudentScopeDecisionPrivateKey    string
	MCPMentorEnabled                     bool
	MCPMentorAuthIssuer                  string
	MCPMentorAuthPublicKey               string
	MCPMentorDecisionPrivateKey          string
	AuthModeratorIss                     string
	AuthModeratorAud                     string
	CacheTTL                             time.Duration
	IDEStudentRoleEnabled                bool
	IDEStudentRoleToken                  string
	MentorOwner                          MentorOwnerConfig
}

// Load reads configuration from environment variables applying defaults where necessary.
func Load() (Config, error) {
	cfg := Config{
		AppEnv:                               getEnv("APP_ENV", "dev"),
		HTTPAddr:                             getEnv("HTTP_ADDR", ":8080"),
		DBDSN:                                os.Getenv("DB_DSN"),
		NATSURL:                              getEnv("NATS_URL", "nats://nats:4222"),
		AuthSignupPublicKey:                  os.Getenv("AUTH_SIGNUP_PUBLIC_KEY"),
		AuthJWTPublicKey:                     os.Getenv("AUTH_JWT_PUBLIC_KEY"),
		AuthJWTIssuer:                        getEnv("AUTH_JWT_ISSUER", "auth-service"),
		ReviewerPermissionDecisionPrivateKey: os.Getenv("RBAC_REVIEWER_PERMISSION_DECISION_PRIVATE_KEY"),
		MCPStudentRoleDecisionPrivateKey:     os.Getenv("RBAC_MCP_STUDENT_ROLE_DECISION_PRIVATE_KEY"),
		MCPStudentScopeDecisionPrivateKey:    os.Getenv("RBAC_MCP_STUDENT_SCOPE_DECISION_PRIVATE_KEY"),
		MCPMentorAuthIssuer:                  os.Getenv("RBAC_MCP_MENTOR_AUTH_ISSUER"),
		MCPMentorAuthPublicKey:               os.Getenv("RBAC_MCP_MENTOR_AUTH_PUBLIC_KEY"),
		MCPMentorDecisionPrivateKey:          os.Getenv("RBAC_MCP_MENTOR_DECISION_PRIVATE_KEY"),
		AuthModeratorIss:                     os.Getenv("AUTH_MODERATOR_JWT_ISS"),
		AuthModeratorAud:                     os.Getenv("AUTH_MODERATOR_JWT_AUD"),
	}
	ttl, err := parseDurationSeconds(getEnv("CACHE_TTL_SECONDS", "60"))
	if err != nil {
		return Config{}, fmt.Errorf("invalid CACHE_TTL_SECONDS: %w", err)
	}
	cfg.CacheTTL = ttl
	mcpEnabled, err := strconv.ParseBool(getEnv("MCP_STUDENT_RBAC_ENABLED", "false"))
	if err != nil {
		return Config{}, fmt.Errorf("invalid MCP_STUDENT_RBAC_ENABLED: %w", err)
	}
	cfg.MCPStudentRBACEnabled = mcpEnabled
	mentorMCP := os.Getenv("RBAC_MCP_MENTOR_ENABLED")
	if mentorMCP != "" && mentorMCP != "false" && mentorMCP != "true" {
		return Config{}, fmt.Errorf("RBAC_MCP_MENTOR_ENABLED must be true or false")
	}
	cfg.MCPMentorEnabled = mentorMCP == "true"
	flag := os.Getenv("RBAC_IDE_STUDENT_ROLE_ENABLED")
	if flag != "" && flag != "false" && flag != "true" {
		return Config{}, fmt.Errorf("RBAC_IDE_STUDENT_ROLE_ENABLED must be true or false")
	}
	if flag == "true" {
		token := os.Getenv("RBAC_IDE_STUDENT_ROLE_TOKEN")
		lower := strings.ToLower(token)
		if len(token) < 32 || len(token) > 4096 ||
			strings.Contains(lower, "change-me") || strings.Contains(lower, "placeholder") ||
			strings.Contains(lower, "replace-me") || strings.Contains(lower, "example") ||
			strings.Contains(token, "${") {
			return Config{}, fmt.Errorf("RBAC_IDE_STUDENT_ROLE_TOKEN invalid")
		}
		for _, ch := range token {
			if ch < 33 || ch > 126 {
				return Config{}, fmt.Errorf("RBAC_IDE_STUDENT_ROLE_TOKEN contains unsafe bytes")
			}
		}
		cfg.IDEStudentRoleEnabled = true
		cfg.IDEStudentRoleToken = token
	}
	cfg.MentorOwner, err = loadMentorOwner()
	if err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func parseDurationSeconds(v string) (time.Duration, error) {
	sec, err := strconv.Atoi(v)
	if err != nil {
		return 0, err
	}
	return time.Duration(sec) * time.Second, nil
}
