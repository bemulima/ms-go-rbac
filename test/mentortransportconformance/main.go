//go:build mentortransportconformance

// Test-only private-pipe owner bridge. The actual proof verifier, mutation
// handler/use case/domain planner, signed readback verifier/use case/signer run
// here. The in-memory state below is an explicit fixture, NOT SQL durability,
// broker authentication, a production authority store, or a Gherkin scenario.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"time"

	"github.com/example/ms-rbac-service/internal/domain"
	"github.com/example/ms-rbac-service/internal/infrastructure/client"
	inbound "github.com/example/ms-rbac-service/internal/transport/message/nats"
	"github.com/example/ms-rbac-service/internal/usecase"
)

type state struct {
	mode                 string
	calls, writes, reads int
	receipts             map[string]domain.MentorRoleCommandReceipt
	proofs               map[string]bool
	current              *domain.MentorRoleFence
}

func (s *state) ApplyMentorRole(ctx context.Context, p domain.MentorRoleProof, revalidate domain.MentorRoleProofRevalidator) (domain.MentorRolePlan, error) {
	s.calls++
	s.proofs[p.ProofDigest] = true
	if s.mode == "forbidden" {
		return domain.MentorRolePlan{}, domain.ErrMentorRoleForbidden
	}
	if s.mode == "outage" {
		return domain.MentorRolePlan{}, domain.ErrAuthorityUnavailable
	}
	// Exercise the actual per-invocation revalidator at the three boundaries;
	// no database locks/transactions are claimed by this controlled fixture.
	for range 3 {
		v, err := revalidate(ctx)
		if err != nil {
			return domain.MentorRolePlan{}, err
		}
		if v != p {
			return domain.MentorRolePlan{}, domain.ErrMentorRoleInvalidSnapshot
		}
	}
	var previous *domain.MentorRoleCommandReceipt
	if r, ok := s.receipts[p.Command.RequestID]; ok {
		previous = &r
	}
	plan, err := domain.PlanMentorRoleCommand(p.Command, domain.MentorRoleSnapshot{Receipt: previous, ApplicationFence: s.current, TargetFence: s.current})
	if err != nil {
		return domain.MentorRolePlan{}, err
	}
	if plan.Write {
		s.receipts[p.Command.RequestID] = plan.Receipt
		current := plan.Current
		s.current = &current
		s.writes++
	}
	if s.mode == "lost_ack" {
		s.mode = "normal"
		return domain.MentorRolePlan{}, domain.ErrAuthorityUnavailable
	}
	return plan, nil
}
func (s *state) ReadMentorRole(ctx context.Context, command domain.MentorRoleCommand) (domain.MentorRoleReadbackResult, error) {
	s.reads++
	if ctx.Err() != nil || s.mode == "readback_outage" {
		return domain.MentorRoleReadbackResult{}, domain.ErrAuthorityUnavailable
	}
	if s.current == nil || s.current.Command != command {
		return domain.MentorRoleReadbackResult{}, nil
	}
	return domain.MentorRoleReadbackResult{Confirmed: true, Active: s.current.Active}, nil
}

type frame struct {
	Mode    string          `json:"mode"`
	Subject string          `json:"subject"`
	Body    json.RawMessage `json:"body"`
}
type reply struct {
	Body        json.RawMessage `json:"body,omitempty"`
	Unavailable bool            `json:"unavailable"`
	Calls       int             `json:"calls"`
	Writes      int             `json:"writes"`
	Reads       int             `json:"reads"`
	Proofs      int             `json:"proofs"`
}

func run() error {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 65536)
	if !scanner.Scan() {
		return errors.New("missing fixture config")
	}
	var cfg struct {
		AuthPublic    string `json:"auth_public"`
		RequestPublic string `json:"request_public"`
	}
	if json.Unmarshal(scanner.Bytes(), &cfg) != nil {
		return errors.New("invalid fixture config")
	}
	proofVerifier, err := client.NewAuthMentorRoleProofVerifier(cfg.AuthPublic)
	if err != nil {
		return err
	}
	readVerifier, err := client.NewMentorRoleReadbackProofVerifier(cfg.RequestPublic)
	if err != nil {
		return err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return err
	}
	private := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	public := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}))
	readSigner, err := client.NewMentorRoleReadbackDecisionSigner(private, public)
	if err != nil {
		return err
	}
	s := &state{mode: "normal", receipts: map[string]domain.MentorRoleCommandReceipt{}, proofs: map[string]bool{}}
	mutation := &inbound.MentorRoleMutationConsumer{Mutation: usecase.NewMentorRoleMutation(proofVerifier, s)}
	readback := &inbound.MentorRoleReadbackConsumer{ProofVerifier: readVerifier, Lookup: usecase.NewMentorRoleReadbackLookup(s), DecisionSigner: readSigner}
	out := json.NewEncoder(os.Stdout)
	if err := out.Encode(struct {
		Public string `json:"public_key"`
	}{public}); err != nil {
		return err
	}
	for count := 0; scanner.Scan(); count++ {
		var request frame
		if count > 100 || json.Unmarshal(scanner.Bytes(), &request) != nil {
			return errors.New("invalid fixture frame")
		}
		var body []byte
		var operationErr error
		if request.Mode != "" {
			switch request.Mode {
			case "normal", "forbidden", "outage", "lost_ack", "readback_outage":
				s.mode = request.Mode
			case "stats":
			default:
				return errors.New("invalid fixture mode")
			}
		} else {
			switch request.Subject {
			case inbound.MentorRoleMutationSubject:
				body, operationErr = mutation.Handle(context.Background(), request.Subject, request.Body)
			case domain.MentorRoleReadbackSubject:
				body, operationErr = readback.Handle(context.Background(), request.Subject, request.Body)
			default:
				operationErr = domain.ErrAuthorityUnavailable
			}
		}
		if err := out.Encode(reply{Body: body, Unavailable: operationErr != nil, Calls: s.calls, Writes: s.writes, Reads: s.reads, Proofs: len(s.proofs)}); err != nil {
			return err
		}
	}
	return scanner.Err()
}
func main() {
	guard := time.AfterFunc(45*time.Second, func() { os.Exit(2) })
	defer guard.Stop()
	if run() != nil {
		os.Stderr.WriteString("RBAC transport fixture failed; details withheld\n")
		os.Exit(1)
	}
}
