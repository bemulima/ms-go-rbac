package nats

import (
	"context"
	"errors"
	"time"

	"github.com/example/ms-rbac-service/internal/domain"
	"github.com/example/ms-rbac-service/internal/usecase"
	natsgo "github.com/nats-io/nats.go"
)

const mcpStudentRoleSubject = "rbac.checkMCPStudentRole"

// MCPStudentRoleChecker is a distinct RPC consumer, enabled only under the
// explicit MCP_STUDENT_RBAC_ENABLED bootstrap gate. Legacy unsigned checkRole
// must never authorize an MCP token exchange.
type MCPStudentRoleChecker struct {
	Conn           *natsgo.Conn
	Subject        string
	Queue          string
	ProofVerifier  domain.MCPStudentRoleProofVerifier
	DecisionSigner domain.MCPStudentRoleDecisionSigner
	Principal      *usecase.PrincipalPermissionUsecase
}

type mcpStudentRoleResponse struct {
	DecisionJWT string `json:"decision_jwt,omitempty"`
	Error       string `json:"error,omitempty"`
}

func (c MCPStudentRoleChecker) Listen() error {
	if c.Conn == nil {
		return nil
	}
	if c.Subject != mcpStudentRoleSubject || c.Queue == "" {
		return errors.New("MCP Student RBAC subject and queue must be explicit")
	}
	_, err := c.Conn.QueueSubscribe(c.Subject, c.Queue, func(msg *natsgo.Msg) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = msg.Respond(marshal(c.handle(ctx, msg.Data)))
	})
	return err
}

func (c MCPStudentRoleChecker) handle(ctx context.Context, data []byte) mcpStudentRoleResponse {
	var req permissionCheckRequest // shared exact {"proof":"JWT"} parser
	if ctx == nil || ctx.Err() != nil || len(data) == 0 || len(data) > maxReviewerPermissionRequest ||
		decodePermissionCheckRequest(data, &req) != nil {
		return mcpStudentRoleResponse{Error: "invalid payload"}
	}
	if c.ProofVerifier == nil || c.DecisionSigner == nil || c.Principal == nil {
		return mcpStudentRoleResponse{Error: "MCP Student role lookup unavailable"}
	}
	proof, err := c.ProofVerifier.VerifyMCPStudentRoleProof(ctx, req.Proof)
	if err != nil {
		if errors.Is(err, domain.ErrAuthorityUnavailable) {
			return mcpStudentRoleResponse{Error: "MCP Student role lookup unavailable"}
		}
		return mcpStudentRoleResponse{Error: "MCP Student role lookup denied"}
	}
	allowed, err := c.Principal.HasMCPStudentRole(ctx, proof.Subject)
	if err != nil {
		return mcpStudentRoleResponse{Error: "MCP Student role lookup unavailable"}
	}
	decision, err := c.DecisionSigner.SignMCPStudentRoleDecision(proof, req.Proof, allowed)
	if err != nil || decision == "" {
		return mcpStudentRoleResponse{Error: "MCP Student decision signing unavailable"}
	}
	return mcpStudentRoleResponse{DecisionJWT: decision}
}
