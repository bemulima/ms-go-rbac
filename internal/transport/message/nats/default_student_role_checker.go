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
	natsgo "github.com/nats-io/nats.go"
)

const (
	defaultStudentRoleSubject = "rbac.checkDefaultStudentRole"
	defaultStudentRoleQueue = "ms-go-rbac"
	maxDefaultStudentRolePayload = 256
)

// DefaultStudentRoleReader is deliberately narrower than the legacy
// PrincipalRoleUsecase.Get / GetByRole contract. It MUST resolve only the
// canonical global default scope, with no any-scope fallback.
type DefaultStudentRoleReader interface {
	GetDefaultRole(ctx context.Context, principalID string) (string, error)
}

// DefaultStudentRoleChecker is a dedicated internal NATS read for the public
// Practice catalog boundary. It NEVER modifies or replaces rbac.checkRole.
// Transport requires a private authenticated NATS connection and subject ACL.
type DefaultStudentRoleChecker struct {
	Conn *natsgo.Conn
	Roles DefaultStudentRoleReader
}

type defaultStudentRoleResponse struct {
	OK bool `json:"ok"`
	Role string `json:"role,omitempty"`
	Error string `json:"error,omitempty"`
}

func (checker DefaultStudentRoleChecker) Listen() error {
	if checker.Conn == nil || checker.Roles == nil {
		return errors.New("default Student role checker not configured")
	}
	_, err := checker.Conn.QueueSubscribe(defaultStudentRoleSubject, defaultStudentRoleQueue,
		func(message *natsgo.Msg) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			body, _ := json.Marshal(checker.handle(ctx, message.Data))
			_ = message.Respond(body)
		})
	return err
}

func (checker DefaultStudentRoleChecker) handle(ctx context.Context, body []byte) defaultStudentRoleResponse {
	id, ok := decodeDefaultStudentRoleRequest(body)
	if !ok {
		return defaultStudentRoleResponse{Error: "invalid_payload"}
	}
	if checker.Roles == nil {
		return defaultStudentRoleResponse{Error: "role_check_unavailable"}
	}
	role, err := checker.Roles.GetDefaultRole(ctx, id)
	if err != nil {
		// Never expose SQL, scope, private role assignment or caller identity.
		return defaultStudentRoleResponse{Error: "role_check_unavailable"}
	}
	if role != "student" && role != "student_pro" {
		return defaultStudentRoleResponse{OK: false}
	}
	return defaultStudentRoleResponse{OK: true, Role: role}
}

func decodeDefaultStudentRoleRequest(body []byte) (string, bool) {
	if len(body) == 0 || len(body) > maxDefaultStudentRolePayload {
		return "", false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') || !decoder.More() {
		return "", false
	}
	field, err := decoder.Token()
	if err != nil || field != "user_id" {
		return "", false
	}
	var id string
	if decoder.Decode(&id) != nil || decoder.More() {
		return "", false
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return "", false
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF ||
		!domain.ValidPrincipalID(id) || strings.ToLower(id) != id {
		return "", false
	}
	return id, true
}
