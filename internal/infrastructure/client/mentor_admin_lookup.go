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
	"encoding/pem"
	"errors"
	"strings"
	"time"

	"github.com/example/ms-rbac-service/internal/domain"
)

// AuthMentorAdminLookupProofVerifier accepts only the distinct Auth service
// lookup purpose. The final Mentor role-decision proof is not accepted here.
type AuthMentorAdminLookupProofVerifier struct {
	publicKey *rsa.PublicKey
	now       func() time.Time
}

func NewAuthMentorAdminLookupProofVerifier(publicKeyPEM string) (*AuthMentorAdminLookupProofVerifier, error) {
	verifier := &AuthMentorAdminLookupProofVerifier{now: time.Now}
	if publicKeyPEM == "" {
		return verifier, nil
	}
	if !validMentorAdminPEM(publicKeyPEM, "PUBLIC KEY", "RSA PUBLIC KEY") {
		return nil, errors.New("Mentor Admin lookup key must be one RSA public PEM")
	}
	key, err := parseAuthRSAPublicKey(publicKeyPEM)
	if err != nil {
		return nil, errors.New("Mentor Admin lookup key must be an RSA public key of at least 2048 bits")
	}
	verifier.publicKey = key
	return verifier, nil
}

type mentorAdminLookupClaims struct {
	Issuer    string `json:"iss"`
	Audience  string `json:"aud"`
	ActorID   string `json:"sub"`
	Type      string `json:"typ"`
	Purpose   string `json:"purpose"`
	Subject   string `json:"subject"`
	JWTID     string `json:"jti"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

func (v *AuthMentorAdminLookupProofVerifier) VerifyMentorAdminLookupProof(ctx context.Context, actualSubject, token string) (domain.MentorAdminLookupProof, error) {
	if ctx == nil || ctx.Err() != nil || actualSubject != domain.MentorCanonicalAdminSubject {
		return domain.MentorAdminLookupProof{}, domain.ErrUnauthenticated
	}
	if v == nil || v.publicKey == nil || v.now == nil {
		return domain.MentorAdminLookupProof{}, domain.ErrAuthorityUnavailable
	}
	if len(token) == 0 || len(token) > domain.MentorAdminLookupMaxTokenBytes {
		return domain.MentorAdminLookupProof{}, domain.ErrUnauthenticated
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return domain.MentorAdminLookupProof{}, domain.ErrUnauthenticated
	}
	headerBytes, err := decodeJWTPart(parts[0])
	if err != nil {
		return domain.MentorAdminLookupProof{}, domain.ErrUnauthenticated
	}
	var header mentorRoleJWTHeader
	if strictProofJSON(headerBytes, []string{"alg", "typ"}, &header) != nil || header.Algorithm != "RS256" || header.Type != "JWT" {
		return domain.MentorAdminLookupProof{}, domain.ErrUnauthenticated
	}
	signature, err := decodeJWTPart(parts[2])
	if err != nil || len(signature) != v.publicKey.Size() {
		return domain.MentorAdminLookupProof{}, domain.ErrUnauthenticated
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(v.publicKey, crypto.SHA256, digest[:], signature) != nil {
		return domain.MentorAdminLookupProof{}, domain.ErrUnauthenticated
	}
	// No claims are interpreted and no repository is reachable before the
	// exact signed bytes pass real RSA verification.
	body, err := decodeJWTPart(parts[1])
	if err != nil {
		return domain.MentorAdminLookupProof{}, domain.ErrUnauthenticated
	}
	var claims mentorAdminLookupClaims
	if strictProofJSON(body, []string{"iss", "aud", "sub", "typ", "purpose", "subject", "jti", "iat", "exp"}, &claims) != nil || claims.Issuer != domain.MentorAdminLookupIssuer || claims.Audience != domain.MentorAdminLookupAudience || claims.Type != domain.MentorAdminLookupType || claims.Purpose != domain.MentorAdminLookupPurpose || claims.Subject != actualSubject {
		return domain.MentorAdminLookupProof{}, domain.ErrUnauthenticated
	}
	requestDigest := sha256.Sum256([]byte(token))
	proof := domain.MentorAdminLookupProof{ActorID: claims.ActorID, Subject: claims.Subject, JWTID: claims.JWTID, ProofDigest: hex.EncodeToString(requestDigest[:]), IssuedAt: claims.IssuedAt, ExpiresAt: claims.ExpiresAt}
	if !validMentorAdminRecoveredProof(proof, v.now().Unix()) || ctx.Err() != nil {
		return domain.MentorAdminLookupProof{}, domain.ErrUnauthenticated
	}
	return proof, nil
}

// MentorCanonicalAdminDecisionSigner signs only a point-in-time read result.
// This is not a role-grant receipt or transaction-level Admin authority.
type MentorCanonicalAdminDecisionSigner struct {
	privateKey *rsa.PrivateKey
	now        func() time.Time
}

func NewMentorCanonicalAdminDecisionSigner(privateKeyPEM string) (*MentorCanonicalAdminDecisionSigner, error) {
	signer := &MentorCanonicalAdminDecisionSigner{now: time.Now}
	if privateKeyPEM == "" {
		return signer, nil
	}
	if !validMentorAdminPEM(privateKeyPEM, "PRIVATE KEY", "RSA PRIVATE KEY") {
		return nil, errors.New("Mentor Admin decision key must be one RSA private PEM")
	}
	key, err := parseReviewerPermissionPrivateKey(privateKeyPEM)
	if err != nil {
		return nil, errors.New("Mentor Admin decision key must be an RSA private key of at least 2048 bits")
	}
	signer.privateKey = key
	return signer, nil
}

type mentorAdminDecisionClaims struct {
	Issuer        string `json:"iss"`
	Audience      string `json:"aud"`
	ActorID       string `json:"sub"`
	Type          string `json:"typ"`
	Purpose       string `json:"purpose"`
	Subject       string `json:"subject"`
	Decision      string `json:"decision"`
	JWTID         string `json:"jti"`
	RequestJWTID  string `json:"request_jti"`
	RequestDigest string `json:"request_digest"`
	IssuedAt      int64  `json:"iat"`
	ExpiresAt     int64  `json:"exp"`
}

func (signer *MentorCanonicalAdminDecisionSigner) Sign(ctx context.Context, proof domain.MentorAdminLookupProof, allowed bool) (string, error) {
	if ctx == nil || ctx.Err() != nil || signer == nil || signer.privateKey == nil || signer.now == nil {
		return "", domain.ErrAuthorityUnavailable
	}
	now := signer.now().Unix()
	if !validMentorAdminRecoveredProof(proof, now) || ctx.Err() != nil {
		return "", domain.ErrAuthorityUnavailable
	}
	expires := now + domain.MentorAdminDecisionMaxTTL // bounded positive safe-integer now cannot overflow int64.
	if expires > proof.ExpiresAt {
		expires = proof.ExpiresAt
	}
	jti, err := newReviewerPermissionDecisionJTI()
	if err != nil {
		return "", domain.ErrAuthorityUnavailable
	}
	decision := "DENY"
	if allowed {
		decision = "ALLOW"
	}
	claims := mentorAdminDecisionClaims{Issuer: domain.MentorAdminDecisionIssuer, Audience: domain.MentorAdminDecisionAudience, ActorID: proof.ActorID, Type: domain.MentorAdminDecisionType, Purpose: domain.MentorAdminDecisionPurpose, Subject: proof.Subject, Decision: decision, JWTID: jti, RequestJWTID: proof.JWTID, RequestDigest: proof.ProofDigest, IssuedAt: now, ExpiresAt: expires}
	body, err := json.Marshal(claims)
	if err != nil {
		return "", domain.ErrAuthorityUnavailable
	}
	input := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString(body)
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, signer.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", domain.ErrAuthorityUnavailable
	}
	token := input + "." + base64.RawURLEncoding.EncodeToString(signature)
	finished := signer.now().Unix()
	if ctx.Err() != nil || !validMentorAdminRecoveredProof(proof, finished) || !validMentorAdminTimes(finished, now, expires, domain.MentorAdminDecisionMaxTTL) || len(token) > domain.MentorAdminLookupMaxTokenBytes {
		return "", domain.ErrAuthorityUnavailable
	}
	return token, nil
}

func validMentorAdminRecoveredProof(proof domain.MentorAdminLookupProof, now int64) bool {
	if proof.Subject != domain.MentorCanonicalAdminSubject || !domain.ValidPrincipalID(proof.ActorID) || proof.ActorID != strings.ToLower(proof.ActorID) || !domain.ValidPrincipalID(proof.JWTID) || proof.JWTID != strings.ToLower(proof.JWTID) || len(proof.ProofDigest) != 64 || proof.ProofDigest != strings.ToLower(proof.ProofDigest) {
		return false
	}
	if _, err := hex.DecodeString(proof.ProofDigest); err != nil {
		return false
	}
	return validMentorAdminTimes(now, proof.IssuedAt, proof.ExpiresAt, domain.MentorAdminLookupMaxTTL)
}

func validMentorAdminTimes(now, issued, expires, maxTTL int64) bool {
	if now <= 0 || now > domain.MentorAdminLookupMaxTimestamp || issued <= 0 || issued > domain.MentorAdminLookupMaxTimestamp || expires <= 0 || expires > domain.MentorAdminLookupMaxTimestamp || expires <= now || expires <= issued {
		return false
	}
	return (issued <= now || issued-now <= domain.MentorAdminLookupFutureSkew) && expires-issued <= maxTTL
}

func validMentorAdminPEM(encoded string, types ...string) bool {
	data := bytes.TrimSpace([]byte(encoded))
	block, rest := pem.Decode(data)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 || len(block.Headers) != 0 || !bytes.HasPrefix(data, []byte("-----BEGIN "+block.Type+"-----")) {
		return false
	}
	for _, allowed := range types {
		if block.Type == allowed {
			return true
		}
	}
	return false
}
