package client

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/example/ms-rbac-service/internal/domain"
)

// Dedicated keys and purposes prevent web sessions, Student proofs and Mentor
// role-mutation proofs from being used at this read-only permission boundary.
type MCPMentorAuthority struct {
	public  *rsa.PublicKey
	private *rsa.PrivateKey
	issuer  string
	now     func() time.Time
}

func NewMCPMentorAuthority(authPublic, authIssuer, decisionPrivate string, existingKeys ...string) (*MCPMentorAuthority, error) {
	pub, e1 := parseAuthRSAPublicKey(authPublic)
	priv, e2 := parseReviewerPermissionPrivateKey(decisionPrivate)
	if e1 != nil || e2 != nil || pub == nil || priv == nil || pub.N.BitLen() < 2048 || priv.N.BitLen() < 2048 || pub.N.BitLen() > 8192 || priv.N.BitLen() > 8192 || pub.N.Cmp(priv.N) == 0 || authIssuer == "" || len(authPublic) > 16384 || len(decisionPrivate) > 16384 {
		return nil, domain.ErrAuthorityUnavailable
	}
	for _, encoded := range existingKeys {
		if legacy, err := parseAuthRSAPublicKey(encoded); err == nil && legacy != nil && (legacy.N.Cmp(pub.N) == 0 || legacy.N.Cmp(priv.N) == 0) {
			return nil, domain.ErrAuthorityUnavailable
		}
		if legacy, err := parseReviewerPermissionPrivateKey(encoded); err == nil && legacy != nil && (legacy.N.Cmp(pub.N) == 0 || legacy.N.Cmp(priv.N) == 0) {
			return nil, domain.ErrAuthorityUnavailable
		}
	}
	return &MCPMentorAuthority{public: pub, private: priv, issuer: authIssuer, now: time.Now}, nil
}

type mcpMentorProofClaims struct {
	Issuer    string `json:"iss"`
	Audience  string `json:"aud"`
	Subject   string `json:"sub"`
	Persona   string `json:"persona"`
	Purpose   string `json:"purpose"`
	Scope     string `json:"scope"`
	JWTID     string `json:"jti"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

func (a *MCPMentorAuthority) VerifyMCPMentorProof(ctx context.Context, raw string) (domain.MCPMentorProof, error) {
	denied := domain.MCPMentorProof{}
	if a == nil || a.public == nil || a.now == nil {
		return denied, domain.ErrAuthorityUnavailable
	}
	if ctx == nil || ctx.Err() != nil || len(raw) == 0 || len(raw) > 8192 {
		return denied, domain.ErrUnauthenticated
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return denied, domain.ErrUnauthenticated
	}
	header, err := decodeJWTPart(parts[0])
	if err != nil {
		return denied, domain.ErrUnauthenticated
	}
	var h reviewerPermissionJWTHeader
	if mcpMentorProofJSON(header, []string{"alg", "typ"}, &h) != nil || h.Algorithm != "RS256" || h.Type != "JWT" {
		return denied, domain.ErrUnauthenticated
	}
	data, err := decodeJWTPart(parts[1])
	if err != nil {
		return denied, domain.ErrUnauthenticated
	}
	var c mcpMentorProofClaims
	if mcpMentorProofJSON(data, []string{"iss", "aud", "sub", "persona", "purpose", "scope", "jti", "iat", "exp"}, &c) != nil {
		return denied, domain.ErrUnauthenticated
	}
	sig, err := decodeJWTPart(parts[2])
	hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err != nil || len(sig) != a.public.Size() || rsa.VerifyPKCS1v15(a.public, crypto.SHA256, hash[:], sig) != nil {
		return denied, domain.ErrUnauthenticated
	}
	now := a.now().UTC().Unix()
	if c.Issuer != a.issuer || c.Audience != domain.MCPMentorProofAudience || c.Persona != "MENTOR" || c.Purpose != domain.MCPMentorProofPurpose || !domain.ValidMCPMentorScope(c.Scope) || !validCanonicalReviewerUUID(c.Subject) || !validCanonicalReviewerUUID(c.JWTID) || c.IssuedAt <= 0 || c.IssuedAt > now || c.ExpiresAt <= now || c.ExpiresAt-c.IssuedAt > 15 || c.ExpiresAt > 1<<53-1 || ctx.Err() != nil {
		return denied, domain.ErrUnauthenticated
	}
	digest := sha256.Sum256([]byte(raw))
	return domain.MCPMentorProof{Subject: c.Subject, JWTID: c.JWTID, Digest: hex.EncodeToString(digest[:]), ExpiresAt: c.ExpiresAt, Scope: c.Scope}, nil
}

func (a *MCPMentorAuthority) SignMCPMentorDecision(p domain.MCPMentorProof, access domain.MCPMentorAccess) (string, error) {
	if a == nil || a.private == nil || a.now == nil || !domain.ValidMCPMentorScope(p.Scope) || !validCanonicalReviewerUUID(p.Subject) || !validCanonicalReviewerUUID(p.JWTID) || len(p.Digest) != 64 || (access.Allowed && !access.Active) {
		return "", domain.ErrAuthorityUnavailable
	}
	now := a.now().UTC().Unix()
	expiry := min(now+15, p.ExpiresAt)
	if now <= 0 || expiry <= now {
		return "", domain.ErrAuthorityUnavailable
	}
	jti, err := newReviewerPermissionDecisionJTI()
	if err != nil {
		return "", domain.ErrAuthorityUnavailable
	}
	c := struct {
		mcpMentorProofClaims
		Active        bool   `json:"active"`
		Allowed       bool   `json:"allowed"`
		RequestJWTID  string `json:"request_jti"`
		RequestDigest string `json:"request_digest"`
	}{mcpMentorProofClaims{"ms-go-rbac", domain.MCPMentorDecisionAudience, p.Subject, "MENTOR", domain.MCPMentorDecisionPurpose, p.Scope, jti, now, expiry}, access.Active, access.Allowed, p.JWTID, p.Digest}
	body, err := json.Marshal(c)
	if err != nil {
		return "", domain.ErrAuthorityUnavailable
	}
	message := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString(body)
	hash := sha256.Sum256([]byte(message))
	sig, err := rsa.SignPKCS1v15(rand.Reader, a.private, crypto.SHA256, hash[:])
	if err != nil {
		return "", domain.ErrAuthorityUnavailable
	}
	return message + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func mcpMentorProofJSON(data []byte, fields []string, target any) error {
	if !utf8.Valid(data) || strictProofJSON(data, fields, target) != nil {
		return domain.ErrUnauthenticated
	}
	d := json.NewDecoder(bytes.NewReader(data))
	_, _ = d.Token()
	for d.More() {
		start := d.InputOffset()
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || string(bytes.TrimLeft(data[start:d.InputOffset()], ", \t\r\n")) != "\""+key+"\"" {
			return domain.ErrUnauthenticated
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return domain.ErrUnauthenticated
		}
	}
	return nil
}
