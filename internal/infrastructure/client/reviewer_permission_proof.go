package client

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/example/ms-rbac-service/internal/domain"
)

const maxReviewerPermissionProofBytes = 8 << 10

// AuthReviewerPermissionProofVerifier verifies the short-lived RS256 assertion
// Auth signs after validating the user's session. Only the verified sub is
// returned to the authorization path.
type AuthReviewerPermissionProofVerifier struct {
	publicKey *rsa.PublicKey
	issuer    string
	now       func() time.Time
}

func NewAuthReviewerPermissionProofVerifier(publicKeyPEM, issuer string) (*AuthReviewerPermissionProofVerifier, error) {
	v := &AuthReviewerPermissionProofVerifier{issuer: issuer, now: time.Now}
	if issuer == "" {
		return nil, errors.New("AUTH_JWT_ISSUER must not be empty")
	}
	if publicKeyPEM == "" {
		return v, nil
	}
	key, err := parseAuthRSAPublicKey(publicKeyPEM)
	if err != nil {
		return nil, errors.New("AUTH_JWT_PUBLIC_KEY must be a PEM-encoded RSA public key")
	}
	v.publicKey = key
	return v, nil
}

func parseAuthRSAPublicKey(encoded string) (*rsa.PublicKey, error) {
	block, rest := pem.Decode([]byte(encoded))
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		parsed, err = x509.ParsePKCS1PublicKey(block.Bytes)
	}
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok || key.N == nil || key.N.BitLen() < 2048 || key.E < 3 || key.E%2 == 0 {
		return nil, errors.New("RSA key must be at least 2048 bits")
	}
	return key, nil
}

type reviewerPermissionJWTHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

type reviewerPermissionJWTClaims struct {
	Issuer     string `json:"iss"`
	Audience   string `json:"aud"`
	Subject    string `json:"sub"`
	Type       string `json:"typ"`
	Purpose    string `json:"purpose"`
	Permission string `json:"permission"`
	JWTID      string `json:"jti"`
	IssuedAt   int64  `json:"iat"`
	ExpiresAt  int64  `json:"exp"`
}

func (v *AuthReviewerPermissionProofVerifier) VerifyReviewerPermissionProof(ctx context.Context, token string) (domain.ReviewerPermissionProof, error) {
	if ctx.Err() != nil {
		return domain.ReviewerPermissionProof{}, domain.ErrUnauthenticated
	}
	if v == nil || v.publicKey == nil {
		return domain.ReviewerPermissionProof{}, domain.ErrAuthorityUnavailable
	}
	if len(token) == 0 || len(token) > maxReviewerPermissionProofBytes {
		return domain.ReviewerPermissionProof{}, domain.ErrUnauthenticated
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return domain.ReviewerPermissionProof{}, domain.ErrUnauthenticated
	}
	headerBytes, err := decodeJWTPart(parts[0])
	if err != nil {
		return domain.ReviewerPermissionProof{}, domain.ErrUnauthenticated
	}
	var header reviewerPermissionJWTHeader
	if strictProofJSON(headerBytes, []string{"alg", "typ"}, &header) != nil || header.Algorithm != "RS256" || header.Type != "JWT" {
		return domain.ReviewerPermissionProof{}, domain.ErrUnauthenticated
	}
	claimsBytes, err := decodeJWTPart(parts[1])
	if err != nil {
		return domain.ReviewerPermissionProof{}, domain.ErrUnauthenticated
	}
	var claims reviewerPermissionJWTClaims
	if strictProofJSON(claimsBytes, []string{"iss", "aud", "sub", "typ", "purpose", "permission", "jti", "iat", "exp"}, &claims) != nil {
		return domain.ReviewerPermissionProof{}, domain.ErrUnauthenticated
	}
	signature, err := decodeJWTPart(parts[2])
	if err != nil || len(signature) != v.publicKey.Size() {
		return domain.ReviewerPermissionProof{}, domain.ErrUnauthenticated
	}
	signed := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(signed))
	if err := rsa.VerifyPKCS1v15(v.publicKey, crypto.SHA256, digest[:], signature); err != nil {
		return domain.ReviewerPermissionProof{}, domain.ErrUnauthenticated
	}
	if claims.Issuer != v.issuer || claims.Audience != domain.ReviewerPermissionProofAudience ||
		claims.Type != domain.ReviewerPermissionProofType || claims.Purpose != domain.ReviewerPermissionProofPurpose ||
		claims.Permission != domain.KnowledgeGraphReviewPermission || !validCanonicalReviewerUUID(claims.Subject) ||
		!validCanonicalReviewerUUID(claims.JWTID) {
		return domain.ReviewerPermissionProof{}, domain.ErrUnauthenticated
	}
	now := v.now().Unix()
	if claims.IssuedAt <= 0 || claims.IssuedAt > now+domain.ReviewerPermissionProofFutureSkewSeconds ||
		claims.ExpiresAt <= now || claims.ExpiresAt <= claims.IssuedAt ||
		claims.ExpiresAt-claims.IssuedAt > domain.ReviewerPermissionProofMaxAgeSeconds {
		return domain.ReviewerPermissionProof{}, domain.ErrUnauthenticated
	}
	return domain.ReviewerPermissionProof{Subject: claims.Subject, JWTID: claims.JWTID, Permission: claims.Permission}, nil
}

func validCanonicalReviewerUUID(value string) bool {
	return domain.ValidPrincipalID(value) && value == strings.ToLower(value)
}

func decodeJWTPart(part string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(part)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != part {
		return nil, errors.New("non-canonical JWT encoding")
	}
	return decoded, nil
}

// strictProofJSON accepts exactly one JSON object with the named fields and
// rejects duplicate, unknown, null, or trailing values.
func strictProofJSON(data []byte, required []string, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return errors.New("proof JSON must be an object")
	}
	allowed := make(map[string]struct{}, len(required))
	for _, key := range required {
		allowed[key] = struct{}{}
	}
	seen := make(map[string]struct{}, len(required))
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return errors.New("invalid proof JSON key")
		}
		if _, ok := allowed[key]; !ok {
			return errors.New("unknown proof JSON key")
		}
		if _, ok := seen[key]; ok {
			return errors.New("duplicate proof JSON key")
		}
		seen[key] = struct{}{}
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errors.New("invalid proof JSON value")
		}
	}
	if len(seen) != len(required) {
		return errors.New("missing proof JSON field")
	}
	closing, err := decoder.Token()
	if err != nil {
		return err
	}
	if closing != json.Delim('}') {
		return errors.New("proof JSON object is not closed")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("trailing proof JSON value")
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	return nil
}
