package main

import (
	"net/url"
	"strings"

	"github.com/example/ms-rbac-service/internal/config"
	"github.com/example/ms-rbac-service/internal/domain"
	"github.com/example/ms-rbac-service/internal/infrastructure/client"
	repo "github.com/example/ms-rbac-service/internal/infrastructure/persistence/postgres"
	natstransport "github.com/example/ms-rbac-service/internal/transport/message/nats"
	"github.com/example/ms-rbac-service/internal/usecase"
	"github.com/jackc/pgx/v5/pgxpool"
	natsgo "github.com/nats-io/nats.go"
)

func registerMCPMentorHandler(conn *natsgo.Conn, cfg config.Config, pool *pgxpool.Pool) error {
	if !cfg.MCPMentorEnabled || conn == nil || pool == nil {
		return domain.ErrAuthorityUnavailable
	}
	authority, err := prepareMCPMentorAuthority(cfg)
	if err != nil || authority == nil {
		return domain.ErrAuthorityUnavailable
	}
	checker := natstransport.MCPMentorAccessChecker{Verifier: authority, Signer: authority, Reader: usecase.MCPMentorAccessUsecase{Reader: repo.NewMCPMentorAccessReader(pool)}}
	return checker.Listen(conn)
}

// No database/broker I/O occurs before enabled-only trust validation succeeds.
func prepareMCPMentorAuthority(cfg config.Config) (*client.MCPMentorAuthority, error) {
	if !cfg.MCPMentorEnabled {
		return nil, nil
	}
	issuer, err := url.Parse(cfg.MCPMentorAuthIssuer)
	if cfg.NATSURL == "" || err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.User != nil || issuer.Path != "/mentor" || issuer.RawPath != "" || issuer.RawQuery != "" || issuer.ForceQuery || issuer.Fragment != "" || issuer.Opaque != "" || issuer.String() != cfg.MCPMentorAuthIssuer || len(cfg.MCPMentorAuthIssuer) > 2048 || strings.Contains(cfg.MCPMentorAuthIssuer, "\\") {
		return nil, domain.ErrAuthorityUnavailable
	}
	for _, b := range []byte(cfg.MCPMentorAuthIssuer) {
		if b < 33 || b > 126 {
			return nil, domain.ErrAuthorityUnavailable
		}
	}
	authority, err := client.NewMCPMentorAuthority(cfg.MCPMentorAuthPublicKey, cfg.MCPMentorAuthIssuer, cfg.MCPMentorDecisionPrivateKey, cfg.AuthJWTPublicKey, cfg.MCPStudentRoleDecisionPrivateKey, cfg.MCPStudentScopeDecisionPrivateKey, cfg.ReviewerPermissionDecisionPrivateKey, cfg.MentorOwner.AuthAdminLookupPublicKey, cfg.MentorOwner.AuthRoleDecisionPublicKey, cfg.MentorOwner.ReadbackRequestPublicKey, cfg.MentorOwner.AdminDecisionPublicKey, cfg.MentorOwner.ReadbackDecisionPublicKey)
	if err != nil {
		return nil, err
	}
	return authority, nil
}
