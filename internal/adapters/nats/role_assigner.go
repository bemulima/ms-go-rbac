package nats

import (
	"context"
	"encoding/json"
	"strings"

	natsgo "github.com/nats-io/nats.go"

	"github.com/example/ms-rbac-service/internal/usecase"
)

// RoleAssigner handles rbac.assign-role requests.
type RoleAssigner struct {
	Conn        *natsgo.Conn
	Subject     string
	Queue       string
	PrincipalUC *usecase.PrincipalUsecase
}

type assignRoleRequest struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

type assignRoleResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// Listen subscribes to role assignment requests.
func (c RoleAssigner) Listen() error {
	if c.Conn == nil || c.PrincipalUC == nil {
		return nil
	}
	_, err := c.Conn.QueueSubscribe(c.Subject, c.Queue, func(msg *natsgo.Msg) {
		var req assignRoleRequest
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			_ = msg.Respond(marshal(assignRoleResponse{OK: false, Error: "invalid payload"}))
			return
		}
		req.UserID = strings.TrimSpace(req.UserID)
		req.Role = strings.TrimSpace(req.Role)
		if req.UserID == "" || req.Role == "" {
			_ = msg.Respond(marshal(assignRoleResponse{OK: false, Error: "user_id and role are required"}))
			return
		}
		if err := c.PrincipalUC.AssignRole(context.Background(), req.UserID, req.Role); err != nil {
			_ = msg.Respond(marshal(assignRoleResponse{OK: false, Error: err.Error()}))
			return
		}
		_ = msg.Respond(marshal(assignRoleResponse{OK: true}))
	})
	return err
}
