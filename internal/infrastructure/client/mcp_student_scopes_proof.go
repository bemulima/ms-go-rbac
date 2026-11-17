package client

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/example/ms-rbac-service/internal/domain"
)

// AuthMCPStudentScopeProofVerifier is a dormant verifier for the distinct
// Auth-signed scope request. Role-only and reviewer proofs cannot be reused.
type AuthMCPStudentScopeProofVerifier struct {
	publicKey *rsa.PublicKey
	issuer    string
	now       func() time.Time
}

func NewAuthMCPStudentScopeProofVerifier(publicKeyPEM, issuer string) (*AuthMCPStudentScopeProofVerifier, error) {
	if strings.TrimSpace(issuer) == "" {
		return nil, errors.New("Auth issuer is required for MCP Student scopes")
	}
	verifier := &AuthMCPStudentScopeProofVerifier{issuer: issuer, now: time.Now}
	if publicKeyPEM == "" {
		return verifier, nil // missing authority never validates a proof
	}
	key, err := parseAuthRSAPublicKey(publicKeyPEM)
	if err != nil {
		return nil, errors.New("invalid configured Auth MCP scopes public key")
	}
	verifier.publicKey = key
	return verifier, nil
}

type mcpStudentScopeProofClaims struct {
	Issuer    string   `json:"iss"`
	Audience  string   `json:"aud"`
	Subject   string   `json:"sub"`
	Type      string   `json:"typ"`
	Purpose   string   `json:"purpose"`
	Scopes    []string `json:"scopes"`
	JWTID     string   `json:"jti"`
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
}

func (v *AuthMCPStudentScopeProofVerifier) VerifyMCPStudentScopeProof(ctx context.Context, raw string) (domain.MCPStudentScopeProof, error) {
	denied := domain.MCPStudentScopeProof{}
	if ctx == nil || ctx.Err() != nil {
		return denied, domain.ErrUnauthenticated
	}
	if v == nil || v.publicKey == nil {
		return denied, domain.ErrAuthorityUnavailable
	}
	if len(raw) == 0 || len(raw) > maxReviewerPermissionProofBytes {
		return denied, domain.ErrUnauthenticated
	}
	parts := strings.Split(raw, ".")
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
	var claims mcpStudentScopeProofClaims
	if strictProofJSON(claimsBytes, []string{"iss", "aud", "sub", "typ", "purpose", "scopes", "jti", "iat", "exp"}, &claims) != nil {
		return denied, domain.ErrUnauthenticated
	}
	signature, err := decodeJWTPart(parts[2])
	if err != nil || len(signature) != v.publicKey.Size() {
		return denied, domain.ErrUnauthenticated
	}
	signed := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(signed))
	if rsa.VerifyPKCS1v15(v.publicKey, crypto.SHA256, digest[:], signature) != nil {
		return denied, domain.ErrUnauthenticated
	}
	if claims.Issuer != v.issuer || claims.Audience != domain.MCPStudentScopeProofAudience ||
		claims.Type != domain.MCPStudentScopeProofType || claims.Purpose != domain.MCPStudentScopeProofPurpose ||
		!validCanonicalReviewerUUID(claims.Subject) || !validCanonicalReviewerUUID(claims.JWTID) ||
		!domain.ValidMCPStudentScopeSet(claims.Scopes) {
		return denied, domain.ErrUnauthenticated
	}
	now := v.now().UTC().Unix()
	if claims.IssuedAt <= 0 || claims.IssuedAt > now+domain.MCPStudentScopeProofFutureSkewSeconds ||
		claims.ExpiresAt <= now || claims.ExpiresAt <= claims.IssuedAt ||
		claims.ExpiresAt-claims.IssuedAt > domain.MCPStudentScopeProofMaxAgeSeconds || ctx.Err() != nil {
		return denied, domain.ErrUnauthenticated
	}
	proofHash := sha256.Sum256([]byte(raw))
	return domain.MCPStudentScopeProof{
		Subject: claims.Subject, JWTID: claims.JWTID,
		Requested: append([]string(nil), claims.Scopes...), ProofDigest: hex.EncodeToString(proofHash[:]),
	}, nil
}
