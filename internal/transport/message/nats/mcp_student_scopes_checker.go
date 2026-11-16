package nats

import (
	"context"
	"errors"
	"time"

	"github.com/example/ms-rbac-service/internal/domain"
	"github.com/example/ms-rbac-service/internal/usecase"
	natsgo "github.com/nats-io/nats.go"
)

const mcpStudentScopesSubject = "rbac.checkMCPStudentScopes"

// MCPStudentScopesChecker is a dormant source-only RPC candidate. It is never
// registered in bootstrap and cannot be used as a generic permission lookup.
type MCPStudentScopesChecker struct {
	Conn           *natsgo.Conn
	Subject        string
	Queue          string
	ProofVerifier  domain.MCPStudentScopeProofVerifier
	DecisionSigner domain.MCPStudentScopeDecisionSigner
	Principal      *usecase.PrincipalPermissionUsecase
}

type mcpStudentScopesResponse struct {
	DecisionJWT string `json:"decision_jwt,omitempty"`
	Error       string `json:"error,omitempty"`
}

func (c MCPStudentScopesChecker) Listen() error {
	if c.Conn == nil {
		return nil
	}
	if c.Subject != mcpStudentScopesSubject || c.Queue == "" {
		return errors.New("MCP Student scopes subject and queue must be explicit")
	}
	_, err := c.Conn.QueueSubscribe(c.Subject, c.Queue, func(msg *natsgo.Msg) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = msg.Respond(marshal(c.handle(ctx, msg.Data)))
	})
	return err
}

func (c MCPStudentScopesChecker) handle(ctx context.Context, data []byte) mcpStudentScopesResponse {
	var req permissionCheckRequest // accepts only {"proof":"<JWT>"}
	if ctx == nil || ctx.Err() != nil || len(data) == 0 || len(data) > maxReviewerPermissionRequest ||
		decodePermissionCheckRequest(data, &req) != nil {
		return mcpStudentScopesResponse{Error: "invalid payload"}
	}
	if c.ProofVerifier == nil || c.DecisionSigner == nil || c.Principal == nil {
		return mcpStudentScopesResponse{Error: "MCP Student scope lookup unavailable"}
	}
	proof, err := c.ProofVerifier.VerifyMCPStudentScopeProof(ctx, req.Proof)
	if err != nil {
		if errors.Is(err, domain.ErrAuthorityUnavailable) {
			return mcpStudentScopesResponse{Error: "MCP Student scope lookup unavailable"}
		}
		return mcpStudentScopesResponse{Error: "MCP Student scope lookup denied"}
	}
	allowed, err := c.Principal.AllowedMCPStudentReadScopes(ctx, proof.Subject, proof.Requested)
	if err != nil {
		return mcpStudentScopesResponse{Error: "MCP Student scope lookup unavailable"}
	}
	decision, err := c.DecisionSigner.SignMCPStudentScopeDecision(proof, req.Proof, allowed)
	if err != nil || decision == "" {
		return mcpStudentScopesResponse{Error: "MCP Student scope signing unavailable"}
	}
	return mcpStudentScopesResponse{DecisionJWT: decision}
}
