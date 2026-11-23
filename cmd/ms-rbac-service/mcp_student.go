package main

import (
	"errors"

	"github.com/example/ms-rbac-service/internal/config"
	"github.com/example/ms-rbac-service/internal/infrastructure/client"
	natstransport "github.com/example/ms-rbac-service/internal/transport/message/nats"
	"github.com/example/ms-rbac-service/internal/usecase"
	natsgo "github.com/nats-io/nats.go"
)

// registerMCPStudentHandlers is opt-in. The service must never start a
// partially authorized MCP endpoint when keys or the broker are unavailable.
func registerMCPStudentHandlers(conn *natsgo.Conn, cfg config.Config, principal *usecase.PrincipalPermissionUsecase) error {
	if conn == nil || principal == nil || !cfg.MCPStudentRBACEnabled ||
		cfg.AuthJWTPublicKey == "" || cfg.AuthJWTIssuer == "" ||
		cfg.MCPStudentRoleDecisionPrivateKey == "" ||
		cfg.MCPStudentScopeDecisionPrivateKey == "" {
		return errors.New("MCP Student RBAC prerequisites unavailable")
	}

	roleVerifier, err := client.NewAuthMCPStudentRoleProofVerifier(cfg.AuthJWTPublicKey, cfg.AuthJWTIssuer)
	if err != nil || roleVerifier == nil {
		return errors.New("MCP Student role proof authority unavailable")
	}
	roleSigner, err := client.NewMCPStudentRoleDecisionSigner(cfg.MCPStudentRoleDecisionPrivateKey)
	if err != nil || roleSigner == nil {
		return errors.New("MCP Student role decision authority unavailable")
	}
	scopeVerifier, err := client.NewAuthMCPStudentScopeProofVerifier(cfg.AuthJWTPublicKey, cfg.AuthJWTIssuer)
	if err != nil || scopeVerifier == nil {
		return errors.New("MCP Student scope proof authority unavailable")
	}
	scopeSigner, err := client.NewMCPStudentScopeDecisionSigner(cfg.MCPStudentScopeDecisionPrivateKey)
	if err != nil || scopeSigner == nil {
		return errors.New("MCP Student scope decision authority unavailable")
	}

	roleHandler := natstransport.MCPStudentRoleChecker{
		Conn: conn, Subject: "rbac.checkMCPStudentRole", Queue: "ms-go-rbac",
		ProofVerifier: roleVerifier, DecisionSigner: roleSigner, Principal: principal,
	}
	if err := roleHandler.Listen(); err != nil {
		return errors.New("MCP Student role RPC subscription unavailable")
	}
	scopeHandler := natstransport.MCPStudentScopesChecker{
		Conn: conn, Subject: "rbac.checkMCPStudentScopes", Queue: "ms-go-rbac",
		ProofVerifier: scopeVerifier, DecisionSigner: scopeSigner, Principal: principal,
	}
	if err := scopeHandler.Listen(); err != nil {
		return errors.New("MCP Student scope RPC subscription unavailable")
	}
	return nil
}
