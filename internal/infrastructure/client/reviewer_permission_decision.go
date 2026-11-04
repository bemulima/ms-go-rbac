package client

import (
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
	"strings"
	"time"

	"github.com/example/ms-rbac-service/internal/domain"
)

// ReviewerPermissionDecisionSigner signs the decision returned over the
// request/reply permission channel. An empty key leaves the reply disabled.
type ReviewerPermissionDecisionSigner struct {
	privateKey *rsa.PrivateKey
	now        func() time.Time
}

func NewReviewerPermissionDecisionSigner(privateKeyPEM string) (*ReviewerPermissionDecisionSigner, error) {
	if strings.TrimSpace(privateKeyPEM) == "" {
		return nil, nil
	}
	key, err := parseReviewerPermissionPrivateKey(privateKeyPEM)
	if err != nil {
		return nil, errors.New("RBAC reviewer permission decision key must be a PEM-encoded RSA private key")
	}
	return &ReviewerPermissionDecisionSigner{privateKey: key, now: time.Now}, nil
}

type reviewerPermissionDecisionClaims struct {
	Issuer        string `json:"iss"`
	Audience      string `json:"aud"`
	Subject       string `json:"sub"`
	Type          string `json:"typ"`
	Purpose       string `json:"purpose"`
	Permission    string `json:"permission"`
	Decision      string `json:"decision"`
	JWTID         string `json:"jti"`
	RequestJWTID  string `json:"request_jti"`
	RequestDigest string `json:"request_digest"`
	IssuedAt      int64  `json:"iat"`
	ExpiresAt     int64  `json:"exp"`
}

func (signer *ReviewerPermissionDecisionSigner) Sign(proof domain.ReviewerPermissionProof, rawProof string, allowed bool) (string, error) {
	if signer == nil || signer.privateKey == nil || !domain.ValidPrincipalID(proof.Subject) ||
		!domain.ValidPrincipalID(proof.JWTID) || proof.Permission != domain.KnowledgeGraphReviewPermission || rawProof == "" {
		return "", domain.ErrAuthorityUnavailable
	}
	nowFn := signer.now
	if nowFn == nil {
		nowFn = time.Now
	}
	now := nowFn().UTC().Truncate(time.Second)
	decision, digest := "DENY", sha256.Sum256([]byte(rawProof))
	if allowed {
		decision = "ALLOW"
	}
	responseJTI, err := newReviewerPermissionDecisionJTI()
	if err != nil {
		return "", err
	}
	claims := reviewerPermissionDecisionClaims{
		Issuer: domain.ReviewerPermissionDecisionIssuer, Audience: domain.ReviewerPermissionDecisionAudience,
		Subject: proof.Subject, Type: domain.ReviewerPermissionDecisionType,
		Purpose: domain.ReviewerPermissionDecisionPurpose, Permission: domain.KnowledgeGraphReviewPermission,
		Decision: decision, JWTID: responseJTI, RequestJWTID: proof.JWTID,
		RequestDigest: hex.EncodeToString(digest[:]), IssuedAt: now.Unix(),
		ExpiresAt: now.Add(domain.ReviewerPermissionDecisionTTLSeconds * time.Second).Unix(),
	}
	header := base64.RawURLEncoding.EncodeToString([]byte("{\"alg\":\"RS256\",\"typ\":\"JWT\"}"))
	claimBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(claimBytes)
	unsigned := header + "." + payload
	hash := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, signer.privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func parseReviewerPermissionPrivateKey(encoded string) (*rsa.PrivateKey, error) {
	block, rest := pem.Decode([]byte(encoded))
	if block == nil || len(rest) > 0 && strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("invalid PEM")
	}
	var key *rsa.PrivateKey
	var err error
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		var parsed any
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil {
			var ok bool
			key, ok = parsed.(*rsa.PrivateKey)
			if !ok {
				err = errors.New("private key is not RSA")
			}
		}
	default:
		return nil, errors.New("unsupported PEM block type")
	}
	if err != nil || key == nil || key.N.BitLen() < 2048 {
		return nil, fmt.Errorf("invalid RSA private key")
	}
	if err := key.Validate(); err != nil {
		return nil, errors.New("invalid RSA private key")
	}
	return key, nil
}

func newReviewerPermissionDecisionJTI() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16]), nil
}
