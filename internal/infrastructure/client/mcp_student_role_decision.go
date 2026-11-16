package client

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/example/ms-rbac-service/internal/domain"
)

// MCPStudentRoleDecisionSigner is deliberately not wired into service startup.
// Its future key is RBAC-only, and its audience cannot authorize reviewer or
// generic role APIs. It asserts a role, NEVER an MCP scope entitlement.
type MCPStudentRoleDecisionSigner struct {
	privateKey *rsa.PrivateKey
	now        func() time.Time
}

func NewMCPStudentRoleDecisionSigner(privateKeyPEM string) (*MCPStudentRoleDecisionSigner, error) {
	if strings.TrimSpace(privateKeyPEM) == "" {
		return nil, nil // dormant without separately configured RBAC key
	}
	key, err := parseReviewerPermissionPrivateKey(privateKeyPEM)
	if err != nil {
		return nil, errors.New("invalid MCP Student RBAC decision key")
	}
	return &MCPStudentRoleDecisionSigner{privateKey: key, now: time.Now}, nil
}

type mcpStudentRoleDecisionClaims struct {
	Issuer        string `json:"iss"`
	Audience      string `json:"aud"`
	Subject       string `json:"sub"`
	Type          string `json:"typ"`
	Purpose       string `json:"purpose"`
	Role          string `json:"role"`
	Decision      string `json:"decision"`
	JWTID         string `json:"jti"`
	RequestJWTID  string `json:"request_jti"`
	RequestDigest string `json:"request_digest"`
	IssuedAt      int64  `json:"iat"`
	ExpiresAt     int64  `json:"exp"`
}

func (signer *MCPStudentRoleDecisionSigner) SignMCPStudentRoleDecision(proof domain.MCPStudentRoleProof, rawProof string, allowed bool) (string, error) {
	if signer == nil || signer.privateKey == nil || rawProof == "" ||
		!validCanonicalReviewerUUID(proof.Subject) || !validCanonicalReviewerUUID(proof.JWTID) {
		return "", domain.ErrAuthorityUnavailable
	}
	now := signer.now().UTC().Truncate(time.Second)
	requestDigest := sha256.Sum256([]byte(rawProof))
	responseJTI, err := newReviewerPermissionDecisionJTI()
	if err != nil {
		return "", err
	}
	decision := "DENY"
	if allowed {
		decision = "ALLOW"
	}
	claims := mcpStudentRoleDecisionClaims{
		Issuer: domain.MCPStudentRoleDecisionIssuer, Audience: domain.MCPStudentRoleDecisionAudience,
		Subject: proof.Subject, Type: domain.MCPStudentRoleDecisionType,
		Purpose: domain.MCPStudentRoleDecisionPurpose, Role: domain.MCPStudentRole,
		Decision: decision, JWTID: responseJTI, RequestJWTID: proof.JWTID,
		RequestDigest: hex.EncodeToString(requestDigest[:]), IssuedAt: now.Unix(),
		ExpiresAt: now.Add(domain.MCPStudentRoleDecisionTTLSeconds * time.Second).Unix(),
	}
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signed := header + "." + payload
	digest := sha256.Sum256([]byte(signed))
	signature, err := rsa.SignPKCS1v15(rand.Reader, signer.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}
