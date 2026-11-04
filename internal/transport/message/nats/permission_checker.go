package nats

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/example/ms-rbac-service/internal/domain"
	"github.com/example/ms-rbac-service/internal/usecase"
	natsgo "github.com/nats-io/nats.go"
)

const (
	reviewerPermissionSubject    = "rbac.checkPermission"
	maxReviewerPermissionRequest = 9 << 10
)

// PermissionChecker serves the fixed knowledge_graph.review lookup. Auth must
// provide a short-lived signed proof; the reviewer subject and permission are
// never accepted as independent caller-controlled request fields.
type PermissionChecker struct {
	Conn           *natsgo.Conn
	Subject        string
	Queue          string
	ProofVerifier  domain.ReviewerPermissionProofVerifier
	DecisionSigner domain.ReviewerPermissionDecisionSigner
	Permission     *usecase.PrincipalPermissionUsecase
}

type permissionCheckRequest struct {
	Proof string `json:"proof"`
}

type permissionCheckResponse struct {
	DecisionJWT string `json:"decision_jwt,omitempty"`
	Error       string `json:"error,omitempty"`
}

// Listen registers a queue-group request/reply permission lookup.
func (c PermissionChecker) Listen() error {
	if c.Conn == nil {
		return nil
	}
	if c.Subject != reviewerPermissionSubject {
		return errors.New("permission lookup subject must be rbac.checkPermission")
	}
	if c.Queue == "" {
		return errors.New("permission lookup queue is required")
	}
	_, err := c.Conn.QueueSubscribe(c.Subject, c.Queue, func(msg *natsgo.Msg) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = msg.Respond(marshal(c.handle(ctx, msg.Data)))
	})
	return err
}

func (c PermissionChecker) handle(ctx context.Context, data []byte) permissionCheckResponse {
	var req permissionCheckRequest
	if len(data) == 0 || len(data) > maxReviewerPermissionRequest || decodePermissionCheckRequest(data, &req) != nil {
		return permissionCheckResponse{Error: "invalid payload"}
	}
	if c.ProofVerifier == nil || c.DecisionSigner == nil || c.Permission == nil {
		return permissionCheckResponse{Error: "permission lookup unavailable"}
	}
	proof, err := c.ProofVerifier.VerifyReviewerPermissionProof(ctx, req.Proof)
	if err != nil {
		if errors.Is(err, domain.ErrAuthorityUnavailable) {
			return permissionCheckResponse{Error: "permission lookup unavailable"}
		}
		return permissionCheckResponse{Error: "permission lookup denied"}
	}
	allowed, err := c.Permission.HasKnowledgeGraphReview(ctx, proof.Subject)
	if err != nil {
		return permissionCheckResponse{Error: "permission lookup unavailable"}
	}
	decision, err := c.DecisionSigner.Sign(proof, req.Proof, allowed)
	if err != nil || decision == "" {
		return permissionCheckResponse{Error: "permission decision signing unavailable"}
	}
	return permissionCheckResponse{DecisionJWT: decision}
}

func decodePermissionCheckRequest(data []byte, target *permissionCheckRequest) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return errors.New("permission request must be an object")
	}
	seenProof := false
	for decoder.More() {
		token, err := decoder.Token()
		field, ok := token.(string)
		if err != nil || !ok || field != "proof" || seenProof {
			return errors.New("permission request has an unknown or duplicate field")
		}
		seenProof = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errors.New("permission proof is invalid")
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') || !seenProof {
		return errors.New("permission request is incomplete")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("permission request has trailing data")
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil || strings.TrimSpace(target.Proof) == "" {
		return errors.New("permission proof is invalid")
	}
	return nil
}
