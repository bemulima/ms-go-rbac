package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/example/ms-rbac-service/internal/domain"
	natstransport "github.com/example/ms-rbac-service/internal/transport/message/nats"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMentorOwnerCompositionDisabledMakesNoCalls(t *testing.T) {
	pool := &mentorCompositionPoolProbe{}
	for _, cfg := range []MentorOwnerCompositionConfig{{}, {AuthAdminLookupPublicKeyPEM: "invalid configuration is not consulted"}} {
		composition, err := NewMentorOwnerComposition(cfg, pool)
		if err != nil || composition != nil || composition.Subjects() != nil {
			t.Fatal("disabled construction must return no handlers")
		}
		body, err := composition.Handle(context.Background(), domain.MentorCanonicalAdminSubject, []byte(`{"proof":"invalid"}`))
		if body != nil || err != domain.ErrAuthorityUnavailable {
			t.Fatal("disabled dispatcher must fail closed")
		}
	}
	if pool.calls() != 0 {
		t.Fatal("disabled composition accessed its pool")
	}
	var typedNil *mentorCompositionPoolProbe
	if composition, err := NewMentorOwnerComposition(MentorOwnerCompositionConfig{}, typedNil); composition != nil || err != nil {
		t.Fatal("disabled composition must not inspect even a typed-nil dependency")
	}
}

func TestMentorOwnerCompositionRejectsIncompleteConfiguration(t *testing.T) {
	keys := mentorCompositionKeys(t)
	base := mentorCompositionConfig(t, keys)
	var typedNil *mentorCompositionPoolProbe
	var pgxNil *pgxpool.Pool
	for name, pool := range map[string]MentorOwnerPool{"nil": nil, "typed_nil": typedNil, "pgx_typed_nil": pgxNil} {
		t.Run(name, func(t *testing.T) {
			composition, err := NewMentorOwnerComposition(base, pool)
			if composition != nil || err != domain.ErrAuthorityUnavailable {
				t.Fatal("missing pool must fail construction")
			}
		})
	}
	for _, field := range []string{"AuthAdminLookupPublicKeyPEM", "AuthRoleDecisionPublicKeyPEM", "MentorReadbackPublicKeyPEM", "AdminDecisionPrivateKeyPEM", "AdminDecisionPublicKeyPEM", "ReadbackDecisionPrivateKeyPEM", "ReadbackDecisionPublicKeyPEM"} {
		for _, invalid := range []string{"", "not a key"} {
			t.Run(field+fmt.Sprintf("_length_%d", len(invalid)), func(t *testing.T) {
				cfg := base
				reflect.ValueOf(&cfg).Elem().FieldByName(field).SetString(invalid)
				pool := &mentorCompositionPoolProbe{}
				composition, err := NewMentorOwnerComposition(cfg, pool)
				if composition != nil || err != domain.ErrAuthorityUnavailable || pool.calls() != 0 {
					t.Fatal("incomplete keys must fail closed before all pool calls")
				}
			})
		}
	}
	for _, field := range []string{"AdminDecisionPrivateKeyPEM", "ReadbackDecisionPrivateKeyPEM"} {
		t.Run("mismatched_"+field, func(t *testing.T) {
			cfg := base
			reflect.ValueOf(&cfg).Elem().FieldByName(field).SetString(mentorCompositionPrivatePEM(keys[0]))
			pool := &mentorCompositionPoolProbe{}
			composition, err := NewMentorOwnerComposition(cfg, pool)
			if composition != nil || err != domain.ErrAuthorityUnavailable || pool.calls() != 0 {
				t.Fatal("both owner reply pairs must be matched before construction")
			}
		})
	}
}

func TestMentorOwnerCompositionSeparatesEveryPurposeByRSAModulus(t *testing.T) {
	keys := mentorCompositionKeys(t)
	for target := 1; target < len(keys); target++ {
		for source := 0; source < target; source++ {
			t.Run(fmt.Sprintf("purpose_%d_reuses_%d", target, source), func(t *testing.T) {
				reused := keys
				reused[target] = reused[source]
				pool := &mentorCompositionPoolProbe{}
				composition, err := NewMentorOwnerComposition(mentorCompositionConfig(t, reused), pool)
				if composition != nil || err != domain.ErrAuthorityUnavailable || pool.calls() != 0 {
					t.Fatal("each of the five purpose keys must have a distinct modulus")
				}
			})
		}
	}
	for _, exponent := range []int{keys[0].E, keys[0].E + 2} {
		t.Run(fmt.Sprintf("same_modulus_pkcs1_exponent_%d", exponent), func(t *testing.T) {
			cfg := mentorCompositionConfig(t, keys)
			alias := rsa.PublicKey{N: keys[0].N, E: exponent}
			cfg.AuthRoleDecisionPublicKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&alias)}))
			composition, err := NewMentorOwnerComposition(cfg, &mentorCompositionPoolProbe{})
			if composition != nil || err != domain.ErrAuthorityUnavailable {
				t.Fatal("PEM encoding or exponent differences cannot hide modulus reuse")
			}
		})
	}
}

func TestMentorOwnerCompositionFixedDispatchRejectsBeforeStorage(t *testing.T) {
	keys := mentorCompositionKeys(t)
	pool := &mentorCompositionPoolProbe{}
	composition, err := NewMentorOwnerComposition(mentorCompositionConfig(t, keys), pool)
	if err != nil || composition == nil || pool.calls() != 0 {
		t.Fatal("valid construction must assemble handlers without pool I/O")
	}
	want := []string{domain.MentorCanonicalAdminSubject, natstransport.MentorRoleMutationSubject, domain.MentorRoleReadbackSubject}
	if !reflect.DeepEqual(composition.Subjects(), want) {
		t.Fatal("only the exact three owned subjects may be exposed")
	}
	returned := composition.Subjects()
	returned[0] = "rbac.assign-role"
	if !reflect.DeepEqual(composition.Subjects(), want) {
		t.Fatal("returned subjects must not permit mutation of the bindings")
	}
	validAdmin := mentorCompositionProofEnvelope(t, keys, domain.MentorCanonicalAdminSubject)
	for _, subject := range []string{"", "rbac.assign-role", "rbac.checkRole", "rbac.*", ">", " " + domain.MentorCanonicalAdminSubject, domain.MentorCanonicalAdminSubject + ".alias", strings.ToUpper(domain.MentorCanonicalAdminSubject)} {
		t.Run("subject_"+subject, func(t *testing.T) {
			body, err := composition.Handle(context.Background(), subject, validAdmin)
			if body != nil || err != domain.ErrAuthorityUnavailable || pool.calls() != 0 {
				t.Fatal("actual subject must not be replaced by a configured alias")
			}
		})
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, cancelled} {
		body, err := composition.Handle(ctx, domain.MentorCanonicalAdminSubject, validAdmin)
		if body != nil || err != domain.ErrAuthorityUnavailable || pool.calls() != 0 {
			t.Fatal("unavailable context must stop before the concrete owner")
		}
	}
	if (&MentorOwnerComposition{}).Subjects() != nil {
		t.Fatal("zero-value composition cannot expose partial handlers")
	}
	for _, subject := range want {
		t.Run("invalid_proof_"+subject, func(t *testing.T) {
			body, err := composition.Handle(context.Background(), subject, []byte(`{"proof":"invalid"}`))
			if subject == natstransport.MentorRoleMutationSubject {
				if err != nil || string(body) != `{"error":"invalid_proof"}` {
					t.Fatal("mutation consumer's exact unauthenticated reply was not preserved")
				}
			} else if body != nil || err != domain.ErrAuthorityUnavailable {
				t.Fatal("lookup must not sign an invalid proof result")
			}
			if pool.calls() != 0 {
				t.Fatal("proof admission must precede all storage")
			}
		})
	}
	for _, subject := range []string{natstransport.MentorRoleMutationSubject, domain.MentorRoleReadbackSubject} {
		body, err := composition.Handle(context.Background(), subject, validAdmin)
		if subject == natstransport.MentorRoleMutationSubject {
			if err != nil || string(body) != `{"error":"invalid_proof"}` {
				t.Fatal("Auth Admin lookup proof must not authorize a mutation")
			}
		} else if body != nil || err != domain.ErrAuthorityUnavailable {
			t.Fatal("Auth Admin lookup proof must not authorize Mentor scoped readback")
		}
	}
	if pool.calls() != 0 {
		t.Fatal("cross-purpose proof reached storage")
	}
}

func TestMentorOwnerCompositionCallsCanonicalAdminRepositoryAndSigner(t *testing.T) {
	keys := mentorCompositionKeys(t)
	for _, test := range []struct {
		name    string
		role    string
		count   int64
		failure error
		want    string
	}{
		{"admin", "admin", 1, nil, "ALLOW"},
		{"student", "student", 1, nil, "DENY"},
		{"ambiguous", "admin", 2, nil, ""},
		{"dependency", "", 0, errors.New("private database diagnostic"), ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			pool := &mentorCompositionPoolProbe{role: test.role, count: test.count, rowError: test.failure}
			composition, err := NewMentorOwnerComposition(mentorCompositionConfig(t, keys), pool)
			if err != nil {
				t.Fatal("composition failed")
			}
			request := mentorCompositionProofEnvelope(t, keys, domain.MentorCanonicalAdminSubject)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			body, err := composition.Handle(ctx, domain.MentorCanonicalAdminSubject, request)
			if pool.queries != 1 || pool.begins != 0 || len(pool.transactions) != 0 || !strings.Contains(pool.query, "COUNT(*)") || strings.Contains(pool.query, "LIMIT 1") {
				t.Fatal("actual unique GetDefaultRole must be the only repository path")
			}
			wantArgs := []any{mentorCompositionActorID, "user", "00000000-0000-0000-0000-000000000000", "00000000-0000-0000-0000-000000000100", "global", "00000000-0000-0000-0000-000000000000"}
			if !reflect.DeepEqual(pool.args, wantArgs) {
				t.Fatal("canonical-default tuple or authenticated actor was not preserved")
			}
			deadline, _ := ctx.Deadline()
			if pool.deadline.IsZero() || pool.deadline.After(deadline) {
				t.Fatal("caller deadline was extended")
			}
			if test.want == "" {
				if body != nil || err != domain.ErrAuthorityUnavailable {
					t.Fatal("ambiguous or unavailable storage cannot become signed DENY")
				}
				return
			}
			if err != nil {
				t.Fatal("known canonical result must be signed by the configured owner")
			}
			claims := mentorCompositionDecision(t, body, &keys[3].PublicKey)
			var envelope struct {
				Proof string `json:"proof"`
			}
			if json.Unmarshal(request, &envelope) != nil {
				t.Fatal("bad test envelope")
			}
			digest := sha256.Sum256([]byte(envelope.Proof))
			if claims["decision"] != test.want || claims["sub"] != mentorCompositionActorID || claims["request_jti"] != mentorCompositionNonce || claims["request_digest"] != hex.EncodeToString(digest[:]) || claims["purpose"] != domain.MentorAdminDecisionPurpose {
				t.Fatal("wrong owner signer or exact request binding")
			}
		})
	}
}

func TestMentorOwnerCompositionCallsConcreteMutationAndReadbackStores(t *testing.T) {
	keys := mentorCompositionKeys(t)
	for _, test := range []struct {
		subject   string
		isolation pgx.TxIsoLevel
		access    pgx.TxAccessMode
	}{
		{natstransport.MentorRoleMutationSubject, pgx.ReadCommitted, pgx.ReadWrite},
		{domain.MentorRoleReadbackSubject, pgx.RepeatableRead, pgx.ReadOnly},
	} {
		t.Run(test.subject, func(t *testing.T) {
			pool := &mentorCompositionPoolProbe{}
			composition, err := NewMentorOwnerComposition(mentorCompositionConfig(t, keys), pool)
			if err != nil || pool.calls() != 0 {
				t.Fatal("constructor must not call storage")
			}
			body, err := composition.Handle(context.Background(), test.subject, mentorCompositionProofEnvelope(t, keys, test.subject))
			if len(pool.transactions) != 1 || pool.begins != 0 || pool.queries != 0 || pool.transactions[0].IsoLevel != test.isolation || pool.transactions[0].AccessMode != test.access {
				t.Fatal("valid dedicated proof did not enter the correct concrete owner adapter")
			}
			if pool.deadline.IsZero() || time.Until(pool.deadline) > 5*time.Second {
				t.Fatal("owner operation must keep a bounded context")
			}
			// The fixture deliberately refuses BeginTx. This proves composition,
			// not SQL, a successful grant, or a signed owner readback.
			if test.subject == natstransport.MentorRoleMutationSubject {
				if err != nil || string(body) != `{"error":"unavailable"}` {
					t.Fatal("store unavailability must remain an unresolved mutation")
				}
			} else if err != domain.ErrAuthorityUnavailable || body != nil {
				t.Fatal("failed snapshot must not produce signed readback")
			}
		})
	}
}

const (
	mentorCompositionActorID = "11111111-1111-4111-8111-111111111111"
	mentorCompositionNonce   = "55555555-5555-4555-8555-555555555555"
)

type mentorCompositionPoolProbe struct {
	begins       int
	queries      int
	transactions []pgx.TxOptions
	query        string
	args         []any
	deadline     time.Time
	role         string
	count        int64
	rowError     error
}

func (p *mentorCompositionPoolProbe) Begin(context.Context) (pgx.Tx, error) {
	p.begins++
	return nil, errors.New("unexpected legacy transaction")
}

func (p *mentorCompositionPoolProbe) BeginTx(ctx context.Context, options pgx.TxOptions) (pgx.Tx, error) {
	p.transactions = append(p.transactions, options)
	p.deadline, _ = ctx.Deadline()
	return nil, errors.New("private database diagnostic: no database was opened")
}

func (p *mentorCompositionPoolProbe) QueryRow(ctx context.Context, query string, args ...any) pgx.Row {
	p.queries++
	p.query = query
	p.args = append([]any(nil), args...)
	p.deadline, _ = ctx.Deadline()
	return mentorCompositionRow{role: p.role, count: p.count, err: p.rowError}
}

func (p *mentorCompositionPoolProbe) calls() int { return p.begins + p.queries + len(p.transactions) }

type mentorCompositionRow struct {
	role  string
	count int64
	err   error
}

func (r mentorCompositionRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != 2 {
		return errors.New("unexpected noncanonical lookup")
	}
	role, roleOK := dest[0].(*string)
	count, countOK := dest[1].(*int64)
	if !roleOK || !countOK {
		return errors.New("unexpected lookup destination")
	}
	*role, *count = r.role, r.count
	return nil
}

var mentorCompositionKeyFixture struct {
	once sync.Once
	keys [5]*rsa.PrivateKey
	err  error
}

func mentorCompositionKeys(t *testing.T) [5]*rsa.PrivateKey {
	t.Helper()
	mentorCompositionKeyFixture.once.Do(func() {
		for i := range mentorCompositionKeyFixture.keys {
			mentorCompositionKeyFixture.keys[i], mentorCompositionKeyFixture.err = rsa.GenerateKey(rand.Reader, 2048)
			if mentorCompositionKeyFixture.err != nil {
				return
			}
		}
	})
	if mentorCompositionKeyFixture.err != nil {
		t.Fatal("cannot generate ephemeral test keys")
	}
	return mentorCompositionKeyFixture.keys
}

func mentorCompositionConfig(t *testing.T, keys [5]*rsa.PrivateKey) MentorOwnerCompositionConfig {
	t.Helper()
	return MentorOwnerCompositionConfig{Enabled: true,
		AuthAdminLookupPublicKeyPEM:   mentorCompositionPublicPEM(t, &keys[0].PublicKey),
		AuthRoleDecisionPublicKeyPEM:  mentorCompositionPublicPEM(t, &keys[1].PublicKey),
		MentorReadbackPublicKeyPEM:    mentorCompositionPublicPEM(t, &keys[2].PublicKey),
		AdminDecisionPrivateKeyPEM:    mentorCompositionPrivatePEM(keys[3]),
		AdminDecisionPublicKeyPEM:     mentorCompositionPublicPEM(t, &keys[3].PublicKey),
		ReadbackDecisionPrivateKeyPEM: mentorCompositionPrivatePEM(keys[4]),
		ReadbackDecisionPublicKeyPEM:  mentorCompositionPublicPEM(t, &keys[4].PublicKey),
	}
}

func mentorCompositionPrivatePEM(key *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
}

func mentorCompositionPublicPEM(t *testing.T, key *rsa.PublicKey) string {
	t.Helper()
	encoded, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal("cannot encode test public key")
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded}))
}

func mentorCompositionProofEnvelope(t *testing.T, keys [5]*rsa.PrivateKey, subject string) []byte {
	t.Helper()
	now := time.Now().Unix()
	claims := map[string]any{"iss": domain.MentorAdminLookupIssuer, "aud": domain.MentorAdminLookupAudience,
		"sub": mentorCompositionActorID, "typ": domain.MentorAdminLookupType, "purpose": domain.MentorAdminLookupPurpose,
		"subject": subject, "jti": mentorCompositionNonce, "iat": now, "exp": now + 30}
	key := keys[0]
	if subject != domain.MentorCanonicalAdminSubject {
		application := "22222222-2222-4222-8222-222222222222"
		target := "33333333-3333-4333-8333-333333333333"
		request := "44444444-4444-4444-8444-444444444444"
		digest := sha256.Sum256([]byte("APPROVE|" + mentorCompositionActorID + "|" + application + "|" + request + "|1"))
		claims["application_id"], claims["application_revision"], claims["decision"] = application, 2, "APPROVE"
		claims["request_id"], claims["decision_digest"] = request, hex.EncodeToString(digest[:])
		if subject == natstransport.MentorRoleMutationSubject {
			key = keys[1]
			delete(claims, "subject")
			claims["aud"], claims["typ"], claims["purpose"] = domain.MentorRoleProofAudience, domain.MentorRoleProofType, domain.MentorRoleProofPurpose
			claims["target_user_id"], claims["role"], claims["service"] = target, domain.MentorRole, domain.MentorRoleService
		} else {
			key = keys[2]
			claims["iss"], claims["aud"], claims["typ"], claims["purpose"] = domain.MentorRoleReadbackIssuer, domain.MentorRoleReadbackAudience, domain.MentorRoleReadbackType, domain.MentorRoleReadbackPurpose
			claims["sub"], claims["admin_actor_id"], claims["role_key"], claims["service_key"] = target, mentorCompositionActorID, domain.MentorRole, domain.MentorRoleService
		}
	}
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatal("cannot encode test claims")
	}
	unsigned := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString(body)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal("cannot sign ephemeral test proof")
	}
	envelope, err := json.Marshal(map[string]string{"proof": unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)})
	if err != nil {
		t.Fatal("cannot encode proof envelope")
	}
	return envelope
}

func mentorCompositionDecision(t *testing.T, envelope []byte, key *rsa.PublicKey) map[string]any {
	t.Helper()
	var reply struct {
		Decision string `json:"decision_jwt"`
	}
	if json.Unmarshal(envelope, &reply) != nil {
		t.Fatal("invalid decision envelope")
	}
	parts := strings.Split(reply.Decision, ".")
	if len(parts) != 3 {
		t.Fatal("invalid signed owner decision")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err != nil || rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) != nil {
		t.Fatal("wrong configured decision signer")
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	if err != nil || json.Unmarshal(body, &claims) != nil {
		t.Fatal("invalid decision claims")
	}
	return claims
}
