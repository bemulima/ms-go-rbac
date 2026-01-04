package nats

import (
	"context"
	"encoding/json"

	natsgo "github.com/nats-io/nats.go"

	"github.com/example/ms-rbac-service/internal/usecase"
)

// RoleChecker handles rbac.checkRole requests.
type RoleChecker struct {
	Conn        *natsgo.Conn
	Subject     string
	Queue       string
	PrincipalUC *usecase.PrincipalRoleUsecase
}

type roleCheckRequest struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

type roleCheckResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// Listen subscribes to role check requests.
func (c RoleChecker) Listen() error {
	if c.Conn == nil || c.PrincipalUC == nil {
		return nil
	}
	_, err := c.Conn.QueueSubscribe(c.Subject, c.Queue, func(msg *natsgo.Msg) {
		var req roleCheckRequest
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			_ = msg.Respond(marshal(roleCheckResponse{OK: false, Error: "invalid payload"}))
			return
		}
		ok, err := c.PrincipalUC.GetByRole(context.Background(), req.UserID, req.Role)
		if err != nil {
			_ = msg.Respond(marshal(roleCheckResponse{OK: false, Error: err.Error()}))
			return
		}
		_ = msg.Respond(marshal(roleCheckResponse{OK: ok}))
	})
	return err
}

func marshal(v any) []byte {
	data, _ := json.Marshal(v)
	return data
}
