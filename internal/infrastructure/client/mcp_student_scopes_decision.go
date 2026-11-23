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

// MCPStudentScopeDecisionSigner is not configured or wired into bootstrap.
// Its distinct audience and future dedicated RBAC private key never create
// an OAuth token or assert domain-owner object access.
type MCPStudentScopeDecisionSigner struct {
	privateKey *rsa.PrivateKey
	now        func() time.Time
}

func NewMCPStudentScopeDecisionSigner(privateKeyPEM string) (*MCPStudentScopeDecisionSigner, error) {
	if strings.TrimSpace(privateKeyPEM) == "" {
		return nil, nil // dormant without an RBAC-only private key
	}
	key, err := parseReviewerPermissionPrivateKey(privateKeyPEM)
	if err != nil {
		return nil, errors.New("invalid MCP Student RBAC scope decision key")
	}
	return &MCPStudentScopeDecisionSigner{privateKey: key, now: time.Now}, nil
}

type mcpStudentScopeDecisionClaims struct {
	Issuer          string   `json:"iss"`
	Audience        string   `json:"aud"`
	Subject         string   `json:"sub"`
	Type            string   `json:"typ"`
	Purpose         string   `json:"purpose"`
	RequestedScopes []string `json:"requested_scopes"`
	AllowedScopes   []string `json:"allowed_scopes"`
	JWTID           string   `json:"jti"`
	RequestJWTID    string   `json:"request_jti"`
	RequestDigest   string   `json:"request_digest"`
	IssuedAt        int64    `json:"iat"`
	ExpiresAt       int64    `json:"exp"`
}

func (s *MCPStudentScopeDecisionSigner) SignMCPStudentScopeDecision(proof domain.MCPStudentScopeProof, rawProof string, allowed []string) (string, error) {
	if s == nil || s.privateKey == nil || len(rawProof) == 0 || len(rawProof) > maxReviewerPermissionProofBytes ||
		!validCanonicalReviewerUUID(proof.Subject) || !validCanonicalReviewerUUID(proof.JWTID) ||
		!domain.ValidMCPStudentAllowedScopes(proof.Requested, allowed) {
		return "", domain.ErrAuthorityUnavailable
	}
	proofHash := sha256.Sum256([]byte(rawProof))
	if proof.ProofDigest != hex.EncodeToString(proofHash[:]) {
		return "", domain.ErrAuthorityUnavailable
	}
	nowFn := s.now
	if nowFn == nil {
		nowFn = time.Now
	}
	now := nowFn().UTC().Truncate(time.Second)
	if now.Unix() <= 0 {
		return "", domain.ErrAuthorityUnavailable
	}
	jti, err := newReviewerPermissionDecisionJTI()
	if err != nil {
		return "", domain.ErrAuthorityUnavailable
	}
	claims := mcpStudentScopeDecisionClaims{
		Issuer:          domain.MCPStudentScopeDecisionIssuer,
		Audience:        domain.MCPStudentScopeDecisionAudience,
		Subject:         proof.Subject,
		Type:            domain.MCPStudentScopeDecisionType,
		Purpose:         domain.MCPStudentScopeDecisionPurpose,
		RequestedScopes: append([]string{}, proof.Requested...),
		AllowedScopes:   append([]string{}, allowed...),
		JWTID:           jti,
		RequestJWTID:    proof.JWTID,
		RequestDigest:   proof.ProofDigest,
		IssuedAt:        now.Unix(),
		ExpiresAt:       now.Add(domain.MCPStudentScopeDecisionTTLSeconds * time.Second).Unix(),
	}
	bytes, err := json.Marshal(claims)
	if err != nil {
		return "", domain.ErrAuthorityUnavailable
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	signed := header + "." + base64.RawURLEncoding.EncodeToString(bytes)
	digest := sha256.Sum256([]byte(signed))
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", domain.ErrAuthorityUnavailable
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}
