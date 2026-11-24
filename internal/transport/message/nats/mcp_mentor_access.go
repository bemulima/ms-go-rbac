package nats

import (
	"context"
	"github.com/example/ms-rbac-service/internal/domain"
	natsgo "github.com/nats-io/nats.go"
	"time"
)

type MCPMentorAccessChecker struct {
	Verifier domain.MCPMentorProofVerifier
	Signer   domain.MCPMentorDecisionSigner
	Reader   domain.MCPMentorAccessReader
}

func (c MCPMentorAccessChecker) Listen(conn *natsgo.Conn) error {
	if conn == nil || c.Verifier == nil || c.Signer == nil || c.Reader == nil {
		return domain.ErrAuthorityUnavailable
	}
	_, err := conn.QueueSubscribe(domain.MCPMentorAccessSubject, "ms-go-rbac", func(msg *natsgo.Msg) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = msg.Respond(marshal(c.handle(ctx, msg.Data)))
	})
	return err
}
func (c MCPMentorAccessChecker) handle(ctx context.Context, data []byte) mcpStudentScopesResponse {
	denied := mcpStudentScopesResponse{Error: "MCP Mentor access unavailable"}
	var request permissionCheckRequest
	if ctx == nil || ctx.Err() != nil || len(data) > 9<<10 || decodePermissionCheckRequest(data, &request) != nil || c.Verifier == nil || c.Signer == nil || c.Reader == nil {
		return denied
	}
	proof, err := c.Verifier.VerifyMCPMentorProof(ctx, request.Proof)
	if err != nil {
		return denied
	}
	result, err := c.Reader.ReadMCPMentorAccess(ctx, proof.Subject)
	if err != nil || ctx.Err() != nil {
		return denied
	}
	token, err := c.Signer.SignMCPMentorDecision(proof, result)
	if err != nil || token == "" || ctx.Err() != nil {
		return denied
	}
	return mcpStudentScopesResponse{DecisionJWT: token}
}
