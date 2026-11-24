package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/example/ms-rbac-service/internal/config"
	"github.com/example/ms-rbac-service/internal/domain"
	natstransport "github.com/example/ms-rbac-service/internal/transport/message/nats"
	"github.com/jackc/pgx/v5"
	natsgo "github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

func TestMentorOwnerRuntimeKeepsMCPDecisionKeysSeparate(t *testing.T) {
	cfg := mentorRuntimeConfig(t)
	cfg.MCPStudentRoleDecisionPrivateKey = cfg.MentorOwner.AdminDecisionPrivateKey
	if prepared, err := prepareMentorOwner(cfg); err != nil || prepared == nil {
		t.Fatal("disabled MCP must not change Mentor preflight")
	}
	cfg.MCPStudentRBACEnabled = true
	roleKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	scopeKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cfg.MCPStudentScopeDecisionPrivateKey = mentorCompositionPrivatePEM(scopeKey)
	if prepared, err := prepareMentorOwner(cfg); err != domain.ErrAuthorityUnavailable || prepared != nil {
		t.Fatal("Mentor decision signer must not be reused for MCP role decisions")
	}
	cfg.MCPStudentRoleDecisionPrivateKey = mentorCompositionPrivatePEM(roleKey)
	if prepared, err := prepareMentorOwner(cfg); err != nil || prepared == nil {
		t.Fatal("independently keyed MCP and Mentor must coexist")
	}
	cfg.MCPStudentScopeDecisionPrivateKey = cfg.MentorOwner.ReadbackDecisionPrivateKey
	if prepared, err := prepareMentorOwner(cfg); err != domain.ErrAuthorityUnavailable || prepared != nil {
		t.Fatal("Mentor decision signer must not be reused for MCP scope decisions")
	}
}

func TestMentorOwnerRuntimePreflightDisabledAndSecureOptions(t *testing.T) {
	prepared, err := prepareMentorOwner(config.Config{MentorOwner: config.MentorOwnerConfig{NATSURL: "invalid", NATSCredentialsFile: "/missing"}})
	if err != nil || prepared != nil {
		t.Fatal("disabled feature must not inspect its settings")
	}
	cfg := mentorRuntimeConfig(t)
	prepared, err = prepareMentorOwner(cfg)
	if err != nil || prepared == nil {
		t.Fatal("valid explicit configuration must prepare without network")
	}
	opts := prepared.broker
	if opts.CustomDialer == nil || !opts.SkipHostLookup {
		t.Fatal("initial discovery must not redirect the configured broker endpoint")
	}
	if connection, err := opts.CustomDialer.Dial("tcp", "discovered.invalid:4222"); err != domain.ErrAuthorityUnavailable || connection != nil {
		t.Fatal("a discovered endpoint must be rejected without dialing")
	}
	if opts.ReconnectBufSize != -1 || opts.RetryOnFailedConnect || opts.FlusherTimeout <= 0 || opts.FlusherTimeout > 5*time.Second {
		t.Fatal("new owner transport must explicitly disable buffering/retry and bound flusher")
	}
	if opts.Url != cfg.MentorOwner.NATSURL || !opts.Secure || opts.TLSConfig == nil || opts.TLSConfig.InsecureSkipVerify || opts.TLSConfig.MinVersion < tls.VersionTLS12 || opts.AllowReconnect || opts.Timeout <= 0 || opts.Timeout > 5*time.Second || opts.DrainTimeout > 5*time.Second || opts.UserJWT == nil || opts.SignatureCB == nil || opts.User != "" || opts.Password != "" || opts.Token != "" {
		t.Fatal("dedicated broker must pin verified TLS, user credentials and bounded fail-closed lifecycle")
	}
	jwt, err := opts.UserJWT()
	if err != nil || mentorCredentialUser(jwt) == "" {
		t.Fatal("native credential callbacks were not configured")
	}
	if signature, err := opts.SignatureCB([]byte("public-fixture-challenge")); err != nil || len(signature) == 0 {
		t.Fatal("test-only seed must be usable through the real credential option")
	}
	if !validMentorCompositionKeys(prepared.composition) {
		t.Fatal("prepared owner lost its purpose-separated keys")
	}
	if os.WriteFile(cfg.MentorOwner.NATSCredentialsFile, []byte("replaced test fixture"), 0600) != nil {
		t.Fatal("fixture replacement failed")
	}
	if frozen, err := opts.UserJWT(); err != nil || frozen != jwt {
		t.Fatal("credential callback reread a replaced path instead of using bounded snapshot")
	}
	if _, err := opts.SignatureCB([]byte("public-fixture-challenge")); err != nil {
		t.Fatal("signer reread replaced credential file")
	}
}

func TestMentorOwnerRuntimePreflightRejectsInsecureOrIncompleteSettings(t *testing.T) {
	base := mentorRuntimeConfig(t)
	for _, endpoint := range []string{"", "nats://broker.invalid:4222", "tls://user:secret@broker.invalid:4222", "tls://broker.invalid:4222/path", "tls://broker.invalid:4222?q=x", "tls://broker.invalid:4222#x", "tls://broker.invalid:4222,tls://other.invalid:4222", "tls://broker.invalid", " tls://broker.invalid:4222", "tls://broker.invalid:0"} {
		t.Run("url_"+endpoint, func(t *testing.T) {
			cfg := base
			cfg.MentorOwner.NATSURL = endpoint
			prepared, err := prepareMentorOwner(cfg)
			if prepared != nil || err != domain.ErrAuthorityUnavailable {
				t.Fatal("invalid endpoint must fail with no secret-bearing diagnostic")
			}
		})
	}
	for name, change := range map[string]func(*config.Config){
		"missing_credentials":    func(c *config.Config) { c.MentorOwner.NATSCredentialsFile = "" },
		"relative_credentials":   func(c *config.Config) { c.MentorOwner.NATSCredentialsFile = "test.creds" },
		"unreadable_credentials": func(c *config.Config) { c.MentorOwner.NATSCredentialsFile = "/missing/secret.creds" },
		"directory_credentials":  func(c *config.Config) { c.MentorOwner.NATSCredentialsFile = t.TempDir() },
		"invalid_ca":             func(c *config.Config) { c.MentorOwner.NATSCAFile = c.MentorOwner.NATSCredentialsFile },
		"missing_purpose_key":    func(c *config.Config) { c.MentorOwner.ReadbackRequestPublicKey = "" },
		"reuse_legacy_jwt":       func(c *config.Config) { c.AuthJWTPublicKey = c.MentorOwner.AuthRoleDecisionPublicKey },
		"reuse_legacy_reviewer":  func(c *config.Config) { c.ReviewerPermissionDecisionPrivateKey = c.MentorOwner.AdminDecisionPrivateKey },
		"group_readable_credentials": func(c *config.Config) {
			c.MentorOwner.NATSCredentialsFile = mentorRuntimeCredentials(t)
			if os.Chmod(c.MentorOwner.NATSCredentialsFile, 0640) != nil {
				t.Fatal("test fixture chmod failed")
			}
		},
		"mismatched_broker_seed": func(c *config.Config) {
			c.MentorOwner.NATSCredentialsFile = mentorRuntimeCredentialsWithMismatch(t, true)
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := base
			change(&cfg)
			prepared, err := prepareMentorOwner(cfg)
			if prepared != nil || err != domain.ErrAuthorityUnavailable {
				t.Fatal("unsafe explicit settings must be rejected before any dial")
			}
		})
	}
	for name, contents := range map[string]string{"missing_seed": "test.jwt.fixture", "oversized": strings.Repeat("x", 65537), "empty": ""} {
		t.Run(name, func(t *testing.T) {
			cfg := base
			path := filepath.Join(t.TempDir(), "invalid.creds")
			if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
				t.Fatal("test fixture write failed")
			}
			cfg.MentorOwner.NATSCredentialsFile = path
			prepared, err := prepareMentorOwner(cfg)
			if prepared != nil || err != domain.ErrAuthorityUnavailable {
				t.Fatal("invalid credential file must fail before network")
			}
		})
	}
}

func TestMentorOwnerRuntimeRegistersExactQueuesAndPreservesActualSubject(t *testing.T) {
	prepared, err := prepareMentorOwner(mentorRuntimeConfig(t))
	if err != nil {
		t.Fatal("preparation failed")
	}
	pool := &mentorCompositionPoolProbe{role: "admin", count: 1}
	broker := newMentorRuntimeBroker()
	broker.onSubscribe = func(subject string, callback natsgo.MsgHandler) {
		callback(&natsgo.Msg{Subject: subject, Reply: "_INBOX.test", Data: mentorCompositionProofEnvelope(t, mentorCompositionKeys(t), subject)})
		if pool.calls() != 0 || len(broker.replies) != 0 {
			t.Fatal("callbacks must not be admitted before every registration and flush succeeds")
		}
	}
	runtime, err := startMentorOwner(context.Background(), prepared, pool, broker.dial)
	if err != nil || runtime == nil {
		t.Fatal("explicit owner did not start through injected transport")
	}
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	want := []string{domain.MentorCanonicalAdminSubject, natstransport.MentorRoleMutationSubject, domain.MentorRoleReadbackSubject}
	if !reflect.DeepEqual(broker.subjects, want) || broker.flushes != 1 || pool.calls() != 0 {
		t.Fatal("registration must mount exactly the fixed three consumers with no pool operation")
	}
	for _, queue := range broker.queues {
		if queue != "ms-go-rbac" {
			t.Fatal("Mentor must preserve existing service queue group")
		}
	}
	keys := mentorCompositionKeys(t)
	adminBody := mentorCompositionProofEnvelope(t, keys, domain.MentorCanonicalAdminSubject)
	broker.handlers[domain.MentorCanonicalAdminSubject](&natsgo.Msg{Subject: domain.MentorCanonicalAdminSubject + ".alias", Reply: "_INBOX.test", Data: adminBody})
	if pool.calls() != 0 {
		t.Fatal("subscription constant replaced the actual message subject")
	}
	broker.handlers[domain.MentorCanonicalAdminSubject](&natsgo.Msg{Subject: domain.MentorCanonicalAdminSubject, Reply: "_INBOX.test", Data: adminBody})
	if pool.queries != 1 || len(broker.replies) != 2 {
		t.Fatal("exact request failed to reach actual repository and response path")
	}
	claims := mentorCompositionDecision(t, broker.replies[1], &keys[3].PublicKey)
	if claims["decision"] != "ALLOW" || claims["sub"] != mentorCompositionActorID {
		t.Fatal("owner response did not preserve authenticated binding")
	}
	for _, subject := range want[1:] {
		broker.handlers[subject](&natsgo.Msg{Subject: subject, Reply: "_INBOX.test", Data: mentorCompositionProofEnvelope(t, keys, subject)})
	}
	if len(pool.transactions) != 2 {
		t.Fatal("both remaining fixed subscriptions must reach their real production stores")
	}
	// The actual pool fixture refuses BeginTx. Neither signed inactive state nor
	// successful grant is fabricated; the real parser/store remain in the path.
	if string(broker.replies[2]) != `{"error":"unavailable"}` || string(broker.replies[3]) != `{"error":"unavailable"}` {
		t.Fatal("failed stores must not produce a successful owner reply")
	}
}

func TestMentorOwnerRuntimeStartupFailsClosedWithoutPartialHandlers(t *testing.T) {
	prepared, err := prepareMentorOwner(mentorRuntimeConfig(t))
	if err != nil {
		t.Fatal("preparation failed")
	}
	pool := &mentorCompositionPoolProbe{}
	called := false
	var missingContext context.Context
	if runtime, err := startMentorOwner(missingContext, nil, nil, func(natsgo.Options) (mentorOwnerConnection, error) { called = true; return nil, nil }); runtime != nil || err != nil || called {
		t.Fatal("disabled start must not consult dependencies")
	}
	for _, stage := range []string{"dial", "nil_connection", "anonymous", "unverified_tls", "disconnected", "subscription_1", "subscription_2", "subscription_3", "flush", "last_error", "async_permission"} {
		t.Run(stage, func(t *testing.T) {
			broker := newMentorRuntimeBroker()
			broker.fail = stage
			runtime, err := startMentorOwner(context.Background(), prepared, pool, broker.dial)
			if runtime != nil || err != domain.ErrAuthorityUnavailable {
				t.Fatal("incomplete mount must never return a usable runtime or private diagnostic")
			}
			if stage != "dial" && stage != "nil_connection" && broker.closes != 1 {
				t.Fatal("startup failure must close only its dedicated connection")
			}
			for _, callback := range broker.handlers {
				callback(&natsgo.Msg{Subject: domain.MentorCanonicalAdminSubject, Reply: "_INBOX.test", Data: mentorCompositionProofEnvelope(t, mentorCompositionKeys(t), domain.MentorCanonicalAdminSubject)})
			}
			if pool.calls() != 0 {
				t.Fatal("failed or partial startup must not admit queued callbacks")
			}
		})
	}
	for _, ctx := range []context.Context{nil, func() context.Context { ctx, cancel := context.WithCancel(context.Background()); cancel(); return ctx }()} {
		called = false
		runtime, err := startMentorOwner(ctx, prepared, pool, func(natsgo.Options) (mentorOwnerConnection, error) { called = true; return nil, nil })
		if runtime != nil || err != domain.ErrAuthorityUnavailable || called {
			t.Fatal("missing live lifecycle context must stop before dial")
		}
	}
}

func TestMentorOwnerRuntimeAsyncFailureAndBoundedDrain(t *testing.T) {
	prepared, err := prepareMentorOwner(mentorRuntimeConfig(t))
	if err != nil {
		t.Fatal("preparation failed")
	}
	for _, failure := range []string{"permission", "disconnect", "publish", "drain_error", "drain_timeout", "normal"} {
		t.Run(failure, func(t *testing.T) {
			pool := &mentorCompositionPoolProbe{}
			broker := newMentorRuntimeBroker()
			runtime, err := startMentorOwner(context.Background(), prepared, pool, broker.dial)
			if err != nil {
				t.Fatal("start failed")
			}
			switch failure {
			case "permission":
				broker.opts.AsyncErrorCB(nil, nil, errors.New("private broker error"))
			case "disconnect":
				broker.opts.DisconnectedErrCB(nil, errors.New("private broker error"))
			case "publish":
				broker.fail = failure
				broker.handlers[natstransport.MentorRoleMutationSubject](&natsgo.Msg{Subject: natstransport.MentorRoleMutationSubject, Reply: "_INBOX.test", Data: []byte(`{"proof":"invalid"}`)})
			default:
				broker.fail = failure
			}
			if failure == "permission" || failure == "disconnect" || failure == "publish" {
				select {
				case <-runtime.Done():
				default:
					t.Fatal("async broker failure must stop dedicated owner readiness")
				}
				for _, callback := range broker.handlers {
					callback(&natsgo.Msg{Subject: domain.MentorCanonicalAdminSubject, Reply: "_INBOX.test", Data: mentorCompositionProofEnvelope(t, mentorCompositionKeys(t), domain.MentorCanonicalAdminSubject)})
				}
				if pool.calls() != 0 || broker.closes != 1 {
					t.Fatal("closed runtime kept accepting owner requests")
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			err = runtime.Close(ctx)
			if (failure == "drain_error" || failure == "drain_timeout") && err != domain.ErrAuthorityUnavailable {
				t.Fatal("failed drain must be reported generically")
			}
			if failure == "normal" && err != nil {
				t.Fatal("normal drain must finish successfully")
			}
			if broker.closes != 1 {
				t.Fatal("runtime did not close its dedicated connection exactly once")
			}
			_ = runtime.Close(ctx)
			if broker.closes != 1 {
				t.Fatal("close must be idempotent")
			}
		})
	}
}

func TestMentorOwnerRuntimeDeadlineCancelsOutstandingOwnerCall(t *testing.T) {
	prepared, err := prepareMentorOwner(mentorRuntimeConfig(t))
	if err != nil {
		t.Fatal("preparation failed")
	}
	pool := &mentorRuntimeBlockingPool{entered: make(chan struct{}), cancelled: make(chan struct{})}
	broker := newMentorRuntimeBroker()
	runtime, err := startMentorOwner(context.Background(), prepared, pool, broker.dial)
	if err != nil {
		t.Fatal("start failed")
	}
	broker.fail = "drain_timeout"
	completed := make(chan struct{})
	request := mentorCompositionProofEnvelope(t, mentorCompositionKeys(t), domain.MentorCanonicalAdminSubject)
	go func() {
		defer close(completed)
		broker.handlers[domain.MentorCanonicalAdminSubject](&natsgo.Msg{Subject: domain.MentorCanonicalAdminSubject, Reply: "_INBOX.test", Data: request})
	}()
	select {
	case <-pool.entered:
	case <-time.After(time.Second):
		t.Fatal("owner callback did not reach controlled repository")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if runtime.Close(ctx) != domain.ErrAuthorityUnavailable {
		t.Fatal("uncompleted drain must remain an explicit shutdown error")
	}
	select {
	case <-pool.cancelled:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not cancel outstanding owner context")
	}
	select {
	case <-completed:
	case <-time.After(time.Second):
		t.Fatal("owner callback did not release after cancellation")
	}
	if broker.closes != 1 {
		t.Fatal("deadline must force close only the dedicated connection")
	}
	if len(broker.replies) > 0 && string(broker.replies[0]) != `{"error":"unavailable"}` {
		t.Fatal("cancelled repository must not produce signed authority")
	}
}

func TestMentorOwnerRuntimeInboundLimitsAndPendingLimits(t *testing.T) {
	prepared, err := prepareMentorOwner(mentorRuntimeConfig(t))
	if err != nil {
		t.Fatal("preparation failed")
	}
	pool := &mentorCompositionPoolProbe{role: "admin", count: 1}
	broker := newMentorRuntimeBroker()
	runtime, err := startMentorOwner(context.Background(), prepared, pool, broker.dial)
	if err != nil {
		t.Fatal("start failed")
	}
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	valid := mentorCompositionProofEnvelope(t, mentorCompositionKeys(t), domain.MentorCanonicalAdminSubject)
	for _, reply := range []string{"", "rbac.applyMentorRole.v1", "_INBOX.", "_INBOX.*", "_INBOX.>", "_INBOX.a..b", "_INBOX.a b", "_INBOX.a\nb", "_INBOX." + strings.Repeat("a", 257)} {
		broker.handlers[domain.MentorCanonicalAdminSubject](&natsgo.Msg{Subject: domain.MentorCanonicalAdminSubject, Reply: reply, Data: valid})
	}
	for _, body := range [][]byte{nil, []byte{0xff}, []byte(strings.Repeat("x", 16385))} {
		broker.handlers[domain.MentorCanonicalAdminSubject](&natsgo.Msg{Subject: domain.MentorCanonicalAdminSubject, Reply: "_INBOX.test", Data: body})
	}
	if pool.calls() != 0 || len(broker.replies) != 0 {
		t.Fatal("invalid inbox or envelope must be dropped before consumer/store/reply")
	}
	for _, failure := range []bool{false, true} {
		sub := &mentorRuntimeSubscriptionProbe{fail: failure}
		err := limitMentorSubscription(sub)
		if sub.messages != 128 || sub.bytes != 1<<20 {
			t.Fatal("native subscription pending work must be bounded")
		}
		if failure && (err != domain.ErrAuthorityUnavailable || !sub.unsubscribed) {
			t.Fatal("limits failure must unsubscribe and fail startup")
		}
		if !failure && (err != nil || sub.unsubscribed) {
			t.Fatal("valid limits must preserve exact subscription")
		}
	}
}

type mentorRuntimeSubscriptionProbe struct {
	fail, unsubscribed bool
	messages, bytes    int
}

func (s *mentorRuntimeSubscriptionProbe) SetPendingLimits(messages, bytes int) error {
	s.messages, s.bytes = messages, bytes
	if s.fail {
		return errors.New("private limits diagnostic")
	}
	return nil
}
func (s *mentorRuntimeSubscriptionProbe) Unsubscribe() error { s.unsubscribed = true; return nil }

type mentorRuntimeBlockingPool struct{ entered, cancelled chan struct{} }

func (p *mentorRuntimeBlockingPool) Begin(context.Context) (pgx.Tx, error) {
	return nil, errors.New("not used")
}
func (p *mentorRuntimeBlockingPool) BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error) {
	return nil, errors.New("not used")
}
func (p *mentorRuntimeBlockingPool) QueryRow(ctx context.Context, _ string, _ ...any) pgx.Row {
	close(p.entered)
	<-ctx.Done()
	close(p.cancelled)
	return mentorCompositionRow{err: ctx.Err()}
}

func mentorRuntimeConfig(t *testing.T) config.Config {
	t.Helper()
	keys := mentorCompositionConfig(t, mentorCompositionKeys(t))
	return config.Config{MentorOwner: config.MentorOwnerConfig{
		Enabled: true, NATSURL: "tls://mentor-broker.invalid:4222", NATSCredentialsFile: mentorRuntimeCredentials(t),
		AuthAdminLookupPublicKey: keys.AuthAdminLookupPublicKeyPEM, AuthRoleDecisionPublicKey: keys.AuthRoleDecisionPublicKeyPEM,
		ReadbackRequestPublicKey: keys.MentorReadbackPublicKeyPEM, AdminDecisionPrivateKey: keys.AdminDecisionPrivateKeyPEM,
		AdminDecisionPublicKey: keys.AdminDecisionPublicKeyPEM, ReadbackDecisionPrivateKey: keys.ReadbackDecisionPrivateKeyPEM,
		ReadbackDecisionPublicKey: keys.ReadbackDecisionPublicKeyPEM,
	}}
}

// This fixture is not a broker-issued credential and is never sent to a broker.
// The ephemeral seed proves bounded parsing and native UserJWTAndSeed signing.
func mentorRuntimeCredentials(t *testing.T) string {
	return mentorRuntimeCredentialsWithMismatch(t, false)
}

func mentorRuntimeCredentialsWithMismatch(t *testing.T, mismatch bool) string {
	t.Helper()
	key, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal("ephemeral test key generation failed")
	}
	defer key.Wipe()
	public, err := key.PublicKey()
	if err != nil {
		t.Fatal("ephemeral public key failed")
	}
	if mismatch {
		other, err := nkeys.CreateUser()
		if err != nil {
			t.Fatal("other ephemeral key failed")
		}
		defer other.Wipe()
		public, err = other.PublicKey()
		if err != nil {
			t.Fatal("other ephemeral public key failed")
		}
	}
	claims, err := json.Marshal(map[string]string{"sub": public})
	if err != nil {
		t.Fatal("fixture claims failed")
	}
	jwt := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT","alg":"ed25519-nkey"}`)) + "." + base64.RawURLEncoding.EncodeToString(claims) + ".fixture-signature-not-issued-by-a-broker"
	seed, err := key.Seed()
	if err != nil {
		t.Fatal("ephemeral test key encoding failed")
	}
	defer func() {
		for i := range seed {
			seed[i] = 0
		}
	}()
	path := filepath.Join(t.TempDir(), "test-only.creds")
	body := []byte("-----BEGIN NATS USER JWT-----\n" + jwt + "\n------END NATS USER JWT------\n\n-----BEGIN USER NKEY SEED-----\n" + string(seed) + "\n------END USER NKEY SEED------\n")
	defer func() {
		for i := range body {
			body[i] = 0
		}
	}()
	if os.WriteFile(path, body, 0600) != nil {
		t.Fatal("ephemeral test fixture write failed")
	}
	return path
}

type mentorRuntimeBroker struct {
	opts                    natsgo.Options
	fail                    string
	subjects, queues        []string
	handlers                map[string]natsgo.MsgHandler
	replies                 [][]byte
	flushes, closes, drains int
	closeOnce               sync.Once
	onSubscribe             func(string, natsgo.MsgHandler)
}

func newMentorRuntimeBroker() *mentorRuntimeBroker {
	return &mentorRuntimeBroker{handlers: map[string]natsgo.MsgHandler{}}
}
func (b *mentorRuntimeBroker) dial(opts natsgo.Options) (mentorOwnerConnection, error) {
	b.opts = opts
	if b.fail == "dial" {
		return nil, errors.New("private connection diagnostic")
	}
	if b.fail == "nil_connection" {
		return nil, nil
	}
	if b.fail != "unverified_tls" && opts.TLSConfig != nil && opts.TLSConfig.VerifyConnection != nil {
		if opts.TLSConfig.VerifyConnection(tls.ConnectionState{Version: tls.VersionTLS12, VerifiedChains: [][]*x509.Certificate{{{}}}}) != nil {
			return nil, errors.New("fixture TLS verification failed")
		}
	}
	return b, nil
}
func (b *mentorRuntimeBroker) QueueSubscribe(subject, queue string, callback natsgo.MsgHandler) error {
	b.subjects = append(b.subjects, subject)
	b.queues = append(b.queues, queue)
	b.handlers[subject] = callback
	if b.onSubscribe != nil {
		b.onSubscribe(subject, callback)
	}
	if b.fail == "subscription_"+string(rune('0'+len(b.subjects))) {
		return errors.New("private subscription diagnostic")
	}
	if b.fail == "async_permission" {
		b.opts.AsyncErrorCB(nil, nil, errors.New("private ACL diagnostic"))
	}
	return nil
}
func (b *mentorRuntimeBroker) Publish(_ string, data []byte) error {
	if b.fail == "publish" {
		return errors.New("private publish diagnostic")
	}
	b.replies = append(b.replies, append([]byte(nil), data...))
	return nil
}
func (b *mentorRuntimeBroker) FlushTimeout(time.Duration) error {
	b.flushes++
	if b.fail == "flush" {
		return errors.New("private flush diagnostic")
	}
	return nil
}
func (b *mentorRuntimeBroker) LastError() error {
	if b.fail == "last_error" {
		return errors.New("private asynchronous diagnostic")
	}
	return nil
}
func (b *mentorRuntimeBroker) AuthRequired() bool { return b.fail != "anonymous" }
func (b *mentorRuntimeBroker) TLSConnectionState() (tls.ConnectionState, error) {
	return tls.ConnectionState{}, errors.New("do not poll native TLSConnectionState: pinned library has an unsynchronized status read")
}
func (b *mentorRuntimeBroker) IsConnected() bool { return b.closes == 0 && b.fail != "disconnected" }
func (b *mentorRuntimeBroker) Drain() error {
	b.drains++
	if b.fail == "drain_error" {
		return errors.New("private drain diagnostic")
	}
	if b.fail != "drain_timeout" {
		b.Close()
	}
	return nil
}
func (b *mentorRuntimeBroker) Close() {
	b.closeOnce.Do(func() {
		b.closes++
		if b.opts.ClosedCB != nil {
			b.opts.ClosedCB(nil)
		}
	})
}
