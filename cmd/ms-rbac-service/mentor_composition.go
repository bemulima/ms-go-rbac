package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"reflect"
	"time"

	"github.com/example/ms-rbac-service/internal/domain"
	"github.com/example/ms-rbac-service/internal/infrastructure/client"
	repo "github.com/example/ms-rbac-service/internal/infrastructure/persistence/postgres"
	natstransport "github.com/example/ms-rbac-service/internal/transport/message/nats"
	"github.com/example/ms-rbac-service/internal/usecase"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MentorOwnerCompositionConfig is explicit constructor configuration. The
// default-off executable preflight maps environment settings into this value;
// the constructor itself reads no environment/files and opens no resources.
// All five purpose keys must use different RSA moduli, including aliases encoded
// using another PEM format or exponent. The two owner reply pairs must match.
type MentorOwnerCompositionConfig struct {
	Enabled bool

	AuthAdminLookupPublicKeyPEM   string
	AuthRoleDecisionPublicKeyPEM  string
	MentorReadbackPublicKeyPEM    string
	AdminDecisionPrivateKeyPEM    string
	AdminDecisionPublicKeyPEM     string
	ReadbackDecisionPrivateKeyPEM string
	ReadbackDecisionPublicKeyPEM  string
}

// MentorOwnerPool is the union of the existing concrete repositories' pool
// methods. An already-owned *pgxpool.Pool satisfies it. Construction performs
// no pool operation and never opens, pings, migrates, closes or owns a pool.
type MentorOwnerPool interface {
	Begin(context.Context) (pgx.Tx, error)
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

var _ MentorOwnerPool = (*pgxpool.Pool)(nil)

// MentorOwnerComposition is an unmounted dispatcher, not a NATS connection or
// subscription. Its consumers cannot be replaced through the returned value.
// The explicitly enabled executable runtime mounts this dispatcher unchanged.
type MentorOwnerComposition struct {
	admin    *natstransport.MentorCanonicalAdminConsumer
	mutation *natstransport.MentorRoleMutationConsumer
	readback *natstransport.MentorRoleReadbackConsumer
}

func NewMentorOwnerComposition(cfg MentorOwnerCompositionConfig, pool MentorOwnerPool) (*MentorOwnerComposition, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if missingMentorCompositionPool(pool) || !validMentorCompositionKeys(cfg) {
		return nil, domain.ErrAuthorityUnavailable
	}
	adminVerifier, err := client.NewAuthMentorAdminLookupProofVerifier(cfg.AuthAdminLookupPublicKeyPEM)
	if err != nil {
		return nil, domain.ErrAuthorityUnavailable
	}
	roleVerifier, err := client.NewAuthMentorRoleProofVerifier(cfg.AuthRoleDecisionPublicKeyPEM)
	if err != nil {
		return nil, domain.ErrAuthorityUnavailable
	}
	readbackVerifier, err := client.NewMentorRoleReadbackProofVerifier(cfg.MentorReadbackPublicKeyPEM)
	if err != nil {
		return nil, domain.ErrAuthorityUnavailable
	}
	adminSigner, err := client.NewMentorCanonicalAdminDecisionSigner(cfg.AdminDecisionPrivateKeyPEM)
	if err != nil {
		return nil, domain.ErrAuthorityUnavailable
	}
	readbackSigner, err := client.NewMentorRoleReadbackDecisionSigner(cfg.ReadbackDecisionPrivateKeyPEM, cfg.ReadbackDecisionPublicKeyPEM)
	if err != nil {
		return nil, domain.ErrAuthorityUnavailable
	}

	// Only the concrete canonical-default repository is exposed to this lookup;
	// its legacy Get fallback and general role replacement are not composed.
	adminLookup := usecase.NewMentorCanonicalAdminLookup(repo.NewPrincipalRoleRepository(pool))
	mutation := usecase.NewMentorRoleMutation(roleVerifier, repo.NewMentorRoleStore(pool))
	readback := usecase.NewMentorRoleReadbackLookup(repo.NewMentorRoleReader(pool))
	return &MentorOwnerComposition{
		admin: &natstransport.MentorCanonicalAdminConsumer{
			ProofVerifier: adminVerifier, Lookup: adminLookup, DecisionSigner: adminSigner,
		},
		mutation: &natstransport.MentorRoleMutationConsumer{Mutation: mutation},
		readback: &natstransport.MentorRoleReadbackConsumer{
			ProofVerifier: readbackVerifier, Lookup: readback, DecisionSigner: readbackSigner,
		},
	}, nil
}

// Subjects returns a fresh list of exact bindings. There are no configurable
// aliases, wildcards, legacy subjects or caller-replaceable handlers.
func (c *MentorOwnerComposition) Subjects() []string {
	if !c.ready() {
		return nil
	}
	return []string{domain.MentorCanonicalAdminSubject, natstransport.MentorRoleMutationSubject, domain.MentorRoleReadbackSubject}
}

// Handle passes the actual received subject and body unchanged to its existing
// owner consumer. The explicitly enabled queue subscription supplies msg.Subject,
// never the subscription's constant or a caller header. No subscription is made
// here. The context bound preserves earlier deadlines and is not rollback proof.
func (c *MentorOwnerComposition) Handle(ctx context.Context, actualSubject string, body []byte) ([]byte, error) {
	if !c.ready() || ctx == nil || ctx.Err() != nil {
		return nil, domain.ErrAuthorityUnavailable
	}
	operation, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	switch actualSubject {
	case domain.MentorCanonicalAdminSubject:
		return c.admin.Handle(operation, actualSubject, body)
	case natstransport.MentorRoleMutationSubject:
		return c.mutation.Handle(operation, actualSubject, body)
	case domain.MentorRoleReadbackSubject:
		return c.readback.Handle(operation, actualSubject, body)
	default:
		return nil, domain.ErrAuthorityUnavailable
	}
}

func (c *MentorOwnerComposition) ready() bool {
	return c != nil && c.admin != nil && c.mutation != nil && c.readback != nil
}

func missingMentorCompositionPool(pool MentorOwnerPool) bool {
	if pool == nil {
		return true
	}
	v := reflect.ValueOf(pool)
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return v.IsNil()
	default:
		return false
	}
}

func validMentorCompositionKeys(cfg MentorOwnerCompositionConfig) bool {
	encoded := []string{cfg.AuthAdminLookupPublicKeyPEM, cfg.AuthRoleDecisionPublicKeyPEM,
		cfg.MentorReadbackPublicKeyPEM, cfg.AdminDecisionPublicKeyPEM, cfg.ReadbackDecisionPublicKeyPEM}
	keys := make([]*rsa.PublicKey, len(encoded))
	for i, material := range encoded {
		key := mentorCompositionPublicKey(material)
		if key == nil {
			return false
		}
		for _, previous := range keys[:i] {
			if key.N.Cmp(previous.N) == 0 {
				return false
			}
		}
		keys[i] = key
	}
	return mentorCompositionPairMatches(cfg.AdminDecisionPrivateKeyPEM, keys[3]) &&
		mentorCompositionPairMatches(cfg.ReadbackDecisionPrivateKeyPEM, keys[4])
}

// These helpers validate composition configuration only. JWT verification and
// signing remain exclusively in the existing purpose-specific owner adapters.
func mentorCompositionPublicKey(material string) *rsa.PublicKey {
	block := mentorCompositionPEM(material)
	if block == nil {
		return nil
	}
	var key *rsa.PublicKey
	switch block.Type {
	case "PUBLIC KEY":
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil
		}
		key, _ = parsed.(*rsa.PublicKey)
	case "RSA PUBLIC KEY":
		key, _ = x509.ParsePKCS1PublicKey(block.Bytes)
	}
	if key == nil || key.N == nil || key.N.BitLen() < 2048 || key.E < 3 || key.E%2 == 0 {
		return nil
	}
	return key
}

func mentorCompositionPairMatches(material string, public *rsa.PublicKey) bool {
	block := mentorCompositionPEM(material)
	if block == nil || public == nil {
		return false
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return false
		}
		key, _ = parsed.(*rsa.PrivateKey)
	case "RSA PRIVATE KEY":
		key, _ = x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	return key != nil && key.Validate() == nil && key.PublicKey.Equal(public)
}

func mentorCompositionPEM(material string) *pem.Block {
	encoded := bytes.TrimSpace([]byte(material))
	block, rest := pem.Decode(encoded)
	if block == nil || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 ||
		!bytes.HasPrefix(encoded, []byte("-----BEGIN "+block.Type+"-----")) {
		return nil
	}
	return block
}
