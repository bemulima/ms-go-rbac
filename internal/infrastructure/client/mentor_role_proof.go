package client

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
	"time"

	"github.com/example/ms-rbac-service/internal/domain"
)

const maxMentorRoleProofBytes = 8192

// AuthMentorRoleProofVerifier admits only the separate Mentor Auth assertion.
// It performs no role/receipt access and is not wired into an RPC or HTTP route.
type AuthMentorRoleProofVerifier struct {
	publicKey *rsa.PublicKey
	now       func() time.Time
}

func NewAuthMentorRoleProofVerifier(publicKeyPEM string) (*AuthMentorRoleProofVerifier, error) {
	verifier := &AuthMentorRoleProofVerifier{now: time.Now}
	if publicKeyPEM == "" {
		return verifier, nil
	}
	// Unlike a general JWT key resolver, this constructor pins one separately
	// supplied Mentor public key. It never follows token-provided key metadata.
	encoded := bytes.TrimSpace([]byte(publicKeyPEM))
	block, rest := pem.Decode(encoded)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 || len(block.Headers) != 0 ||
		(block.Type != "PUBLIC KEY" && block.Type != "RSA PUBLIC KEY") ||
		!bytes.HasPrefix(encoded, []byte("-----BEGIN "+block.Type+"-----")) {
		return nil, errors.New("Mentor proof key must be one PEM-encoded RSA public key")
	}
	key, err := parseAuthRSAPublicKey(string(encoded))
	if err != nil {
		return nil, errors.New("Mentor proof key must be an RSA public key of at least 2048 bits")
	}
	verifier.publicKey = key
	return verifier, nil
}

type mentorRoleJWTHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

type mentorRoleJWTClaims struct {
	Issuer              string `json:"iss"`
	Audience            string `json:"aud"`
	Subject             string `json:"sub"`
	Type                string `json:"typ"`
	Purpose             string `json:"purpose"`
	TargetUserID        string `json:"target_user_id"`
	ApplicationID       string `json:"application_id"`
	ApplicationRevision uint64 `json:"application_revision"`
	Decision            string `json:"decision"`
	RequestID           string `json:"request_id"`
	DecisionDigest      string `json:"decision_digest"`
	Role                string `json:"role"`
	Service             string `json:"service"`
	JWTID               string `json:"jti"`
	IssuedAt            int64  `json:"iat"`
	ExpiresAt           int64  `json:"exp"`
}

func (v *AuthMentorRoleProofVerifier) VerifyMentorRoleProof(ctx context.Context, token string) (domain.MentorRoleProof, error) {
	if ctx == nil || ctx.Err() != nil {
		return domain.MentorRoleProof{}, domain.ErrUnauthenticated
	}
	if v == nil || v.publicKey == nil || v.now == nil {
		return domain.MentorRoleProof{}, domain.ErrAuthorityUnavailable
	}
	if len(token) == 0 || len(token) > maxMentorRoleProofBytes {
		return domain.MentorRoleProof{}, domain.ErrUnauthenticated
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return domain.MentorRoleProof{}, domain.ErrUnauthenticated
	}
	headerBytes, err := decodeJWTPart(parts[0])
	if err != nil {
		return domain.MentorRoleProof{}, domain.ErrUnauthenticated
	}
	var header mentorRoleJWTHeader
	if strictProofJSON(headerBytes, []string{"alg", "typ"}, &header) != nil || header.Algorithm != "RS256" || header.Type != "JWT" {
		return domain.MentorRoleProof{}, domain.ErrUnauthenticated
	}
	signature, err := decodeJWTPart(parts[2])
	if err != nil || len(signature) != v.publicKey.Size() {
		return domain.MentorRoleProof{}, domain.ErrUnauthenticated
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(v.publicKey, crypto.SHA256, digest[:], signature) != nil {
		return domain.MentorRoleProof{}, domain.ErrUnauthenticated
	}
	// Signature verification precedes payload interpretation and any possible
	// caller-owned receipt, role or current Admin lookup.
	claimsBytes, err := decodeJWTPart(parts[1])
	if err != nil {
		return domain.MentorRoleProof{}, domain.ErrUnauthenticated
	}
	var claims mentorRoleJWTClaims
	if strictProofJSON(claimsBytes, []string{
		"iss", "aud", "sub", "typ", "purpose", "target_user_id", "application_id", "application_revision",
		"decision", "request_id", "decision_digest", "role", "service", "jti", "iat", "exp",
	}, &claims) != nil {
		return domain.MentorRoleProof{}, domain.ErrUnauthenticated
	}
	command := domain.MentorRoleCommand{
		Issuer: claims.Issuer, AdminID: claims.Subject, TargetUserID: claims.TargetUserID,
		ApplicationID: claims.ApplicationID, ApplicationRevision: claims.ApplicationRevision,
		Decision: claims.Decision, RequestID: claims.RequestID, DecisionDigest: claims.DecisionDigest,
		Role: claims.Role, Service: claims.Service,
	}
	if claims.Audience != domain.MentorRoleProofAudience || claims.Type != domain.MentorRoleProofType || claims.Purpose != domain.MentorRoleProofPurpose ||
		!domain.ValidMentorRoleCommand(command) || !domain.ValidPrincipalID(claims.JWTID) || claims.JWTID != strings.ToLower(claims.JWTID) {
		return domain.MentorRoleProof{}, domain.ErrUnauthenticated
	}
	now := v.now().Unix()
	if now <= 0 || now > domain.MentorRoleProofMaxTimestamp ||
		claims.IssuedAt <= 0 || claims.IssuedAt > domain.MentorRoleProofMaxTimestamp ||
		claims.ExpiresAt <= 0 || claims.ExpiresAt > domain.MentorRoleProofMaxTimestamp ||
		claims.ExpiresAt <= now || claims.ExpiresAt <= claims.IssuedAt {
		return domain.MentorRoleProof{}, domain.ErrUnauthenticated
	}
	// All operands are positive and bounded before subtraction. No now+skew or
	// unvalidated exp-iat arithmetic can overflow into an accepted lifetime.
	if (claims.IssuedAt > now && claims.IssuedAt-now > domain.MentorRoleProofFutureSkewSeconds) ||
		claims.ExpiresAt-claims.IssuedAt > domain.MentorRoleProofMaxAgeSeconds {
		return domain.MentorRoleProof{}, domain.ErrUnauthenticated
	}
	proofDigest := sha256.Sum256([]byte(token))
	if ctx.Err() != nil {
		return domain.MentorRoleProof{}, domain.ErrUnauthenticated
	}
	return domain.MentorRoleProof{Command: command, JWTID: claims.JWTID, ProofDigest: hex.EncodeToString(proofDigest[:]), IssuedAt: claims.IssuedAt, ExpiresAt: claims.ExpiresAt}, nil
}
