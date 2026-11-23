package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/example/ms-rbac-service/internal/config"
	"github.com/example/ms-rbac-service/internal/domain"
	natsgo "github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

// prepareMentorOwner performs only local, explicit configuration validation.
// It is called before opening a database or broker. No credential/key material
// or operator path is returned in an error. Disabled mode reads no files.
func prepareMentorOwner(cfg config.Config) (*mentorOwnerPrepared, error) {
	if !cfg.MentorOwner.Enabled {
		return nil, nil
	}
	c := cfg.MentorOwner
	composition := MentorOwnerCompositionConfig{Enabled: true,
		AuthAdminLookupPublicKeyPEM: c.AuthAdminLookupPublicKey, AuthRoleDecisionPublicKeyPEM: c.AuthRoleDecisionPublicKey,
		MentorReadbackPublicKeyPEM: c.ReadbackRequestPublicKey, AdminDecisionPrivateKeyPEM: c.AdminDecisionPrivateKey,
		AdminDecisionPublicKeyPEM: c.AdminDecisionPublicKey, ReadbackDecisionPrivateKeyPEM: c.ReadbackDecisionPrivateKey,
		ReadbackDecisionPublicKeyPEM: c.ReadbackDecisionPublicKey,
	}
	if !validMentorCompositionKeys(composition) || !mentorKeysSeparateFromLegacy(composition, cfg) {
		return nil, domain.ErrAuthorityUnavailable
	}
	u, err := url.Parse(c.NATSURL)
	if err != nil || u.Scheme != "tls" || u.User != nil || u.Hostname() == "" || u.Path != "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" ||
		strings.ContainsAny(c.NATSURL, ", \t\r\n") {
		return nil, domain.ErrAuthorityUnavailable
	}
	_, port, err := net.SplitHostPort(u.Host)
	number, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || number < 1 || number > 65535 {
		return nil, domain.ErrAuthorityUnavailable
	}
	credential, err := readMentorConfigFile(c.NATSCredentialsFile, 32<<10, true)
	if err != nil {
		return nil, domain.ErrAuthorityUnavailable
	}
	defer wipeMentorConfigBytes(credential)
	jwt, err := nkeys.ParseDecoratedJWT(credential)
	if err != nil {
		return nil, domain.ErrAuthorityUnavailable
	}
	key, err := nkeys.ParseDecoratedUserNKey(credential)
	if err != nil {
		return nil, domain.ErrAuthorityUnavailable
	}
	defer key.Wipe()
	seed, err := key.Seed()
	if err != nil {
		return nil, domain.ErrAuthorityUnavailable
	}
	defer wipeMentorConfigBytes(seed)

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
	if c.NATSCAFile != "" {
		ca, err := readMentorConfigFile(c.NATSCAFile, 1<<20, false)
		if err != nil {
			return nil, domain.ErrAuthorityUnavailable
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(ca) {
			return nil, domain.ErrAuthorityUnavailable
		}
		tlsConfig.RootCAs = roots
	}
	opts := natsgo.GetDefaultOptions()
	opts.Url = c.NATSURL
	opts.SkipHostLookup = true
	opts.CustomDialer = &mentorPinnedDialer{context: context.Background(), address: u.Host}
	opts.ReconnectBufSize = -1
	opts.RetryOnFailedConnect = false
	for _, option := range []natsgo.Option{
		natsgo.Name("ms-go-rbac-mentor-owner"), natsgo.Secure(tlsConfig),
		natsgo.UserJWTAndSeed(jwt, string(seed)), natsgo.NoReconnect(),
		natsgo.Timeout(5 * time.Second), natsgo.DrainTimeout(5 * time.Second),
		natsgo.FlusherTimeout(5 * time.Second),
	} {
		if option(&opts) != nil {
			return nil, domain.ErrAuthorityUnavailable
		}
	}
	// v1.33 has no UserCredentialBytes. Freeze the bounded credential snapshot in
	// its native UserJWTAndSeed callbacks, not a path callback which rereads a
	// potentially replaced secret. This proves local pair consistency only;
	// the authenticated broker still owns JWT issuer/expiry/account/ACL admission.
	challenge := []byte("ms-go-rbac-mentor-owner-local-credential-preflight-v1")
	signature, err := opts.SignatureCB(challenge)
	identity := mentorCredentialUser(jwt)
	if err != nil || identity == "" {
		return nil, domain.ErrAuthorityUnavailable
	}
	verifier, err := nkeys.FromPublicKey(identity)
	if err != nil {
		return nil, domain.ErrAuthorityUnavailable
	}
	defer verifier.Wipe()
	if verifier.Verify(challenge, signature) != nil {
		return nil, domain.ErrAuthorityUnavailable
	}
	return &mentorOwnerPrepared{composition: composition, broker: opts}, nil
}

func mentorKeysSeparateFromLegacy(composition MentorOwnerCompositionConfig, cfg config.Config) bool {
	var legacy []*rsa.PublicKey
	if cfg.AuthJWTPublicKey != "" {
		key := mentorCompositionPublicKey(cfg.AuthJWTPublicKey)
		if key == nil {
			return false
		}
		legacy = append(legacy, key)
	}
	if cfg.ReviewerPermissionDecisionPrivateKey != "" {
		block := mentorCompositionPEM(cfg.ReviewerPermissionDecisionPrivateKey)
		if block == nil {
			return false
		}
		var key *rsa.PrivateKey
		switch block.Type {
		case "RSA PRIVATE KEY":
			key, _ = x509.ParsePKCS1PrivateKey(block.Bytes)
		case "PRIVATE KEY":
			parsed, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
			key, _ = parsed.(*rsa.PrivateKey)
		}
		if key == nil || key.Validate() != nil {
			return false
		}
		legacy = append(legacy, &key.PublicKey)
	}
	for _, material := range []string{composition.AuthAdminLookupPublicKeyPEM, composition.AuthRoleDecisionPublicKeyPEM,
		composition.MentorReadbackPublicKeyPEM, composition.AdminDecisionPublicKeyPEM, composition.ReadbackDecisionPublicKeyPEM} {
		key := mentorCompositionPublicKey(material)
		if key == nil {
			return false
		}
		for _, old := range legacy {
			if old.N.Cmp(key.N) == 0 {
				return false
			}
		}
	}
	return true
}

func readMentorConfigFile(path string, limit int64, secret bool) ([]byte, error) {
	if !filepath.IsAbs(path) || strings.ContainsAny(path, "$~\r\n\x00") {
		return nil, domain.ErrAuthorityUnavailable
	}
	// This Unix service rejects symlinks and opens nonblocking, so a replaced
	// FIFO/device cannot turn configuration preflight into unbounded I/O.
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, domain.ErrAuthorityUnavailable
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit || (secret && info.Mode().Perm()&0077 != 0) {
		return nil, domain.ErrAuthorityUnavailable
	}
	if secret {
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != uint32(os.Geteuid()) {
			return nil, domain.ErrAuthorityUnavailable
		}
	}
	body, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || len(body) == 0 || int64(len(body)) > limit {
		wipeMentorConfigBytes(body)
		return nil, domain.ErrAuthorityUnavailable
	}
	return body, nil
}

// nats.go v1.33 may try INFO-discovered servers even during initial Connect.
// Pin its custom dialer to the operator's one endpoint before any TCP attempt.
// Normal DNS resolution for that hostname is delegated to net.Dialer; discovered
// addresses, network aliases and TLS-handshake bypass are never permitted.
type mentorPinnedDialer struct {
	context            context.Context
	address            string
	attempted          atomic.Bool
	mu                 sync.Mutex
	stopHandshakeGuard func() bool
}

func (d *mentorPinnedDialer) Dial(network, address string) (net.Conn, error) {
	if d == nil || d.context == nil || d.context.Err() != nil || network != "tcp" || address != d.address || d.address == "" || !d.attempted.CompareAndSwap(false, true) {
		return nil, domain.ErrAuthorityUnavailable
	}
	connection, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(d.context, network, address)
	if err != nil {
		return nil, domain.ErrAuthorityUnavailable
	}
	// DialContext stops only the dial. Keep cancellation armed across NATS INFO,
	// authentication and TLS handshakes until the startup path explicitly releases
	// it; cancellation cannot leave an unauthenticated half-open socket behind.
	d.mu.Lock()
	d.stopHandshakeGuard = context.AfterFunc(d.context, func() { _ = connection.Close() })
	d.mu.Unlock()
	return connection, nil
}

func (d *mentorPinnedDialer) releaseHandshakeGuard() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.stopHandshakeGuard != nil && !d.stopHandshakeGuard() {
		return false
	}
	return d.context != nil && d.context.Err() == nil
}

func mentorCredentialUser(jwt string) string {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 || parts[0] == "" || parts[2] == "" {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Subject string `json:"sub"`
	}
	if json.Unmarshal(payload, &claims) != nil || !nkeys.IsValidPublicUserKey(claims.Subject) {
		return ""
	}
	return claims.Subject
}

func wipeMentorConfigBytes(body []byte) {
	for i := range body {
		body[i] = 0
	}
}
