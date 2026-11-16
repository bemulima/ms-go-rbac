package client

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"strings"
	"time"

	"github.com/example/ms-rbac-service/internal/domain"
)

// AuthMCPStudentRoleProofVerifier requires a fresh Auth-signed assertion with
// its own audience/purpose. Reviewer proofs, access JWTs and a raw user ID
// cannot authorize this RBAC lookup.
type AuthMCPStudentRoleProofVerifier struct {
	publicKey *rsa.PublicKey
	issuer    string
	now       func() time.Time
}

func NewAuthMCPStudentRoleProofVerifier(publicKeyPEM, issuer string) (*AuthMCPStudentRoleProofVerifier, error) {
	if strings.TrimSpace(issuer) == "" {
		return nil, errors.New("Auth issuer is required for MCP Student proof")
	}
	verifier := &AuthMCPStudentRoleProofVerifier{issuer: issuer, now: time.Now}
	if publicKeyPEM == "" {
		return verifier, nil // no key means fail-closed; existing RBAC remains unaffected
	}
	key, err := parseAuthRSAPublicKey(publicKeyPEM)
	if err != nil {
		return nil, errors.New("invalid configured Auth MCP proof verification key")
	}
	verifier.publicKey = key
	return verifier, nil
}

type mcpStudentRoleProofClaims struct {
	Issuer    string `json:"iss"`
	Audience  string `json:"aud"`
	Subject   string `json:"sub"`
	Type      string `json:"typ"`
	Purpose   string `json:"purpose"`
	Role      string `json:"role"`
	JWTID     string `json:"jti"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

func (v *AuthMCPStudentRoleProofVerifier) VerifyMCPStudentRoleProof(ctx context.Context, token string) (domain.MCPStudentRoleProof, error) {
	denied := domain.MCPStudentRoleProof{}
	if ctx == nil || ctx.Err() != nil {
		return denied, domain.ErrUnauthenticated
	}
	if v == nil || v.publicKey == nil {
		return denied, domain.ErrAuthorityUnavailable
	}
	if len(token) == 0 || len(token) > maxReviewerPermissionProofBytes {
		return denied, domain.ErrUnauthenticated
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return denied, domain.ErrUnauthenticated
	}
	headerBytes, err := decodeJWTPart(parts[0])
	if err != nil {
		return denied, domain.ErrUnauthenticated
	}
	var header reviewerPermissionJWTHeader
	if strictProofJSON(headerBytes, []string{"alg", "typ"}, &header) != nil || header.Algorithm != "RS256" || header.Type != "JWT" {
		return denied, domain.ErrUnauthenticated
	}
	claimsBytes, err := decodeJWTPart(parts[1])
	if err != nil {
		return denied, domain.ErrUnauthenticated
	}
	var claims mcpStudentRoleProofClaims
	if strictProofJSON(claimsBytes, []string{"iss", "aud", "sub", "typ", "purpose", "role", "jti", "iat", "exp"}, &claims) != nil {
		return denied, domain.ErrUnauthenticated
	}
	signature, err := decodeJWTPart(parts[2])
	if err != nil || len(signature) != v.publicKey.Size() {
		return denied, domain.ErrUnauthenticated
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(v.publicKey, crypto.SHA256, digest[:], signature) != nil {
		return denied, domain.ErrUnauthenticated
	}
	if claims.Issuer != v.issuer || claims.Audience != domain.MCPStudentRoleProofAudience ||
		claims.Type != domain.MCPStudentRoleProofType || claims.Purpose != domain.MCPStudentRoleProofPurpose ||
		claims.Role != domain.MCPStudentRole || !validCanonicalReviewerUUID(claims.Subject) ||
		!validCanonicalReviewerUUID(claims.JWTID) {
		return denied, domain.ErrUnauthenticated
	}
	now := v.now().UTC().Unix()
	if claims.IssuedAt <= 0 || claims.IssuedAt > now+domain.MCPStudentRoleProofFutureSkewSeconds ||
		claims.ExpiresAt <= now || claims.ExpiresAt <= claims.IssuedAt ||
		claims.ExpiresAt-claims.IssuedAt > domain.MCPStudentRoleProofMaxAgeSeconds {
		return denied, domain.ErrUnauthenticated
	}
	return domain.MCPStudentRoleProof{Subject: claims.Subject, JWTID: claims.JWTID}, nil
}
