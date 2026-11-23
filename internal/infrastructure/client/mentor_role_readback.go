package client

import (
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

// MentorRoleReadbackProofVerifier accepts only the dedicated Mentor service
// lookup signature. Neither the target nor original Admin is caller authority.
type MentorRoleReadbackProofVerifier struct {
	publicKey *rsa.PublicKey
	now       func() time.Time
}

func NewMentorRoleReadbackProofVerifier(publicPEM string) (*MentorRoleReadbackProofVerifier, error) {
	if !validMentorAdminPEM(publicPEM, "PUBLIC KEY", "RSA PUBLIC KEY") {
		return nil, domain.ErrAuthorityUnavailable
	}
	key, err := parseAuthRSAPublicKey(publicPEM)
	if err != nil {
		return nil, domain.ErrAuthorityUnavailable
	}
	return &MentorRoleReadbackProofVerifier{publicKey: key, now: time.Now}, nil
}

func (v *MentorRoleReadbackProofVerifier) VerifyMentorRoleReadbackProof(ctx context.Context, actualSubject, token string) (domain.MentorRoleReadbackProof, error) {
	if ctx == nil || ctx.Err() != nil || actualSubject != domain.MentorRoleReadbackSubject {
		return domain.MentorRoleReadbackProof{}, domain.ErrUnauthenticated
	}
	if v == nil || v.publicKey == nil || v.now == nil {
		return domain.MentorRoleReadbackProof{}, domain.ErrAuthorityUnavailable
	}
	if len(token) == 0 || len(token) > domain.MentorRoleReadbackMaxTokenBytes {
		return domain.MentorRoleReadbackProof{}, domain.ErrUnauthenticated
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return domain.MentorRoleReadbackProof{}, domain.ErrUnauthenticated
	}
	headerBytes, err := decodeJWTPart(parts[0])
	var header mentorRoleJWTHeader
	if err != nil || !utf8.Valid(headerBytes) || strictProofJSON(headerBytes, []string{"alg", "typ"}, &header) != nil || header.Algorithm != "RS256" || header.Type != "JWT" {
		return domain.MentorRoleReadbackProof{}, domain.ErrUnauthenticated
	}
	signature, err := decodeJWTPart(parts[2])
	if err != nil || len(signature) != v.publicKey.Size() {
		return domain.MentorRoleReadbackProof{}, domain.ErrUnauthenticated
	}
	signingDigest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(v.publicKey, crypto.SHA256, signingDigest[:], signature) != nil {
		return domain.MentorRoleReadbackProof{}, domain.ErrUnauthenticated
	}
	// Interpret command claims only after the dedicated service signature.
	body, err := decodeJWTPart(parts[1])
	var claims mentorRoleReadbackClaims
	if err != nil || !utf8.Valid(body) || strictProofJSON(body, mentorRoleReadbackRequestFields, &claims) != nil ||
		claims.Issuer != domain.MentorRoleReadbackIssuer || claims.Audience != domain.MentorRoleReadbackAudience ||
		claims.Type != domain.MentorRoleReadbackType || claims.Purpose != domain.MentorRoleReadbackPurpose || claims.Subject != actualSubject {
		return domain.MentorRoleReadbackProof{}, domain.ErrUnauthenticated
	}
	requestDigest := sha256.Sum256([]byte(token))
	proof := domain.MentorRoleReadbackProof{
		Command: domain.MentorRoleCommand{Issuer: domain.MentorRoleProofIssuer, AdminID: claims.AdminID, TargetUserID: claims.TargetUserID,
			ApplicationID: claims.ApplicationID, ApplicationRevision: claims.ApplicationRevision, Decision: claims.Decision,
			RequestID: claims.RequestID, DecisionDigest: claims.DecisionDigest, Role: claims.Role, Service: claims.Service},
		Subject: claims.Subject, JWTID: claims.JWTID, ProofDigest: hex.EncodeToString(requestDigest[:]), IssuedAt: claims.IssuedAt, ExpiresAt: claims.ExpiresAt,
	}
	if !validMentorReadbackProof(proof, v.now().Unix()) || ctx.Err() != nil {
		return domain.MentorRoleReadbackProof{}, domain.ErrUnauthenticated
	}
	return proof, nil
}

// MentorRoleReadbackDecisionSigner attests only a point-in-time owner read.
// It neither applies a role nor extends an expired lookup's authority.
type MentorRoleReadbackDecisionSigner struct {
	privateKey *rsa.PrivateKey
	now        func() time.Time
}

func NewMentorRoleReadbackDecisionSigner(privatePEM, publicPEM string) (*MentorRoleReadbackDecisionSigner, error) {
	if !validMentorAdminPEM(privatePEM, "PRIVATE KEY", "RSA PRIVATE KEY") || !validMentorAdminPEM(publicPEM, "PUBLIC KEY", "RSA PUBLIC KEY") {
		return nil, domain.ErrAuthorityUnavailable
	}
	key, err := parseReviewerPermissionPrivateKey(privatePEM)
	pub, pubErr := parseAuthRSAPublicKey(publicPEM)
	if err != nil || pubErr != nil || key.PublicKey.N.Cmp(pub.N) != 0 || key.PublicKey.E != pub.E {
		return nil, domain.ErrAuthorityUnavailable
	}
	return &MentorRoleReadbackDecisionSigner{privateKey: key, now: time.Now}, nil
}

func (s *MentorRoleReadbackDecisionSigner) Sign(ctx context.Context, proof domain.MentorRoleReadbackProof, result domain.MentorRoleReadbackResult) (string, error) {
	if ctx == nil || ctx.Err() != nil || s == nil || s.privateKey == nil || s.now == nil {
		return "", domain.ErrAuthorityUnavailable
	}
	now := s.now().Unix()
	if !validMentorReadbackProof(proof, now) || !domain.ValidMentorRoleReadbackResult(proof.Command, result) || ctx.Err() != nil {
		return "", domain.ErrAuthorityUnavailable
	}
	expires := proof.ExpiresAt
	if expires-now > domain.MentorRoleReadbackDecisionMaxTTL {
		expires = now + domain.MentorRoleReadbackDecisionMaxTTL
	}
	jti, err := newReviewerPermissionDecisionJTI()
	if err != nil || jti == proof.JWTID {
		return "", domain.ErrAuthorityUnavailable
	}
	decision, state := "DENY", "UNCONFIRMED"
	if result.Confirmed {
		decision, state = "ALLOW", "INACTIVE"
		if result.Active {
			state = "ACTIVE"
		}
	}
	c := proof.Command
	claims := mentorRoleReadbackDecisionClaims{
		mentorRoleReadbackClaims: mentorRoleReadbackClaims{Issuer: domain.MentorRoleReadbackDecisionIssuer, Audience: domain.MentorRoleReadbackDecisionAudience,
			TargetUserID: c.TargetUserID, Type: domain.MentorRoleReadbackDecisionType, Purpose: domain.MentorRoleReadbackDecisionPurpose,
			Subject: proof.Subject, JWTID: jti, IssuedAt: now, ExpiresAt: expires, AdminID: c.AdminID, ApplicationID: c.ApplicationID,
			ApplicationRevision: c.ApplicationRevision, Decision: c.Decision, RequestID: c.RequestID, DecisionDigest: c.DecisionDigest, Role: c.Role, Service: c.Service},
		Result: decision, State: state, RequestJWTID: proof.JWTID, RequestDigest: proof.ProofDigest,
	}
	body, err := json.Marshal(claims)
	if err != nil {
		return "", domain.ErrAuthorityUnavailable
	}
	unsigned := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString(body)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", domain.ErrAuthorityUnavailable
	}
	token := unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
	finished := s.now().Unix()
	if ctx.Err() != nil || !validMentorReadbackProof(proof, finished) || !validMentorReadbackTimes(finished, now, expires, domain.MentorRoleReadbackDecisionMaxTTL) || len(token) > domain.MentorRoleReadbackMaxTokenBytes {
		return "", domain.ErrAuthorityUnavailable
	}
	return token, nil
}

type mentorRoleReadbackClaims struct {
	Issuer              string `json:"iss"`
	Audience            string `json:"aud"`
	TargetUserID        string `json:"sub"`
	Type                string `json:"typ"`
	Purpose             string `json:"purpose"`
	Subject             string `json:"subject"`
	JWTID               string `json:"jti"`
	IssuedAt            int64  `json:"iat"`
	ExpiresAt           int64  `json:"exp"`
	AdminID             string `json:"admin_actor_id"`
	ApplicationID       string `json:"application_id"`
	ApplicationRevision uint64 `json:"application_revision"`
	Decision            string `json:"decision"`
	RequestID           string `json:"request_id"`
	DecisionDigest      string `json:"decision_digest"`
	Role                string `json:"role_key"`
	Service             string `json:"service_key"`
}

type mentorRoleReadbackDecisionClaims struct {
	mentorRoleReadbackClaims
	Result        string `json:"result"`
	State         string `json:"state"`
	RequestJWTID  string `json:"request_jti"`
	RequestDigest string `json:"request_digest"`
}

var mentorRoleReadbackRequestFields = []string{"iss", "aud", "sub", "typ", "purpose", "subject", "jti", "iat", "exp", "admin_actor_id", "application_id", "application_revision", "decision", "request_id", "decision_digest", "role_key", "service_key"}

func validMentorReadbackProof(p domain.MentorRoleReadbackProof, now int64) bool {
	if !domain.ValidMentorRoleCommand(p.Command) || p.Subject != domain.MentorRoleReadbackSubject || !domain.ValidPrincipalID(p.JWTID) || p.JWTID != strings.ToLower(p.JWTID) || len(p.ProofDigest) != 64 || p.ProofDigest != strings.ToLower(p.ProofDigest) {
		return false
	}
	if _, err := hex.DecodeString(p.ProofDigest); err != nil {
		return false
	}
	return validMentorReadbackTimes(now, p.IssuedAt, p.ExpiresAt, domain.MentorRoleReadbackMaxTTL)
}

func validMentorReadbackTimes(now, issued, expires, maxTTL int64) bool {
	if now <= 0 || now > domain.MentorRoleReadbackMaxTimestamp || issued <= 0 || issued > domain.MentorRoleReadbackMaxTimestamp || expires <= 0 || expires > domain.MentorRoleReadbackMaxTimestamp || expires <= now || expires <= issued {
		return false
	}
	return (issued <= now || issued-now <= domain.MentorRoleReadbackFutureSkew) && expires-issued <= maxTTL
}
