package nats

import (
	"context"
	"errors"
	"time"

	"github.com/example/ms-rbac-service/internal/domain"
	natsgo "github.com/nats-io/nats.go"

	"github.com/example/ms-rbac-service/internal/usecase"
)

// RoleAssigner admits only signed canonical Auth signup provisioning.
// The generic principal mutation usecase is never used by this listener.
type RoleAssigner struct {
	Conn     *natsgo.Conn
	Subject  string
	Queue    string
	SignupUC *usecase.SignupProvisioner
}

type assignRoleResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// Listen keeps the consumer registered even when signing authority is unavailable.
func (c RoleAssigner) Listen() error {
	if c.Conn == nil {
		return nil
	}
	if !domain.ValidSignupSubject(c.Subject) {
		return errors.New("signup assignment subject must be concrete")
	}
	_, err := c.Conn.QueueSubscribe(c.Subject, c.Queue, func(msg *natsgo.Msg) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = msg.Respond(marshal(c.handle(ctx, msg.Subject, msg.Data)))
	})
	return err
}

func (c RoleAssigner) handle(ctx context.Context, subject string, data []byte) assignRoleResponse {
	if subject != c.Subject {
		return assignRoleResponse{Error: "signup provisioning denied"}
	}
	err := c.SignupUC.Provision(ctx, subject, data)
	if err == nil {
		return assignRoleResponse{OK: true}
	}
	switch {
	case errors.Is(err, domain.ErrUnauthenticated):
		return assignRoleResponse{Error: "signup provisioning denied"}
	case errors.Is(err, domain.ErrAuthorityUnavailable):
		return assignRoleResponse{Error: "signup provisioning unavailable"}
	case errors.Is(err, domain.ErrSignupConflict):
		return assignRoleResponse{Error: "signup provisioning conflict"}
	default:
		return assignRoleResponse{Error: "signup provisioning failed"}
	}
}
