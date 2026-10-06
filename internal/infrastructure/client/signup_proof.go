package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/example/ms-rbac-service/internal/domain"
)

const (
	maxSignupEnvelopeBytes = 16 << 10
	maxSignupPayloadBytes  = 8 << 10
)

type SignupProofVerifier struct {
	publicKey ed25519.PublicKey
	now       func() time.Time
}

func NewSignupProofVerifier(publicKey string) (*SignupProofVerifier, error) {
	v := &SignupProofVerifier{now: time.Now}
	if publicKey == "" {
		return v, nil
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(publicKey)
	if err != nil || len(decoded) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(decoded) != publicKey {
		return nil, errors.New("AUTH_SIGNUP_PUBLIC_KEY must be a standard base64 Ed25519 public key")
	}
	v.publicKey = ed25519.PublicKey(decoded)
	return v, nil
}

func (v *SignupProofVerifier) VerifySignupProof(ctx context.Context, subject string, data []byte) (domain.SignupGrant, error) {
	if ctx.Err() != nil || v == nil || len(v.publicKey) != ed25519.PublicKeySize {
		return domain.SignupGrant{}, domain.ErrAuthorityUnavailable
	}
	if len(data) == 0 || len(data) > maxSignupEnvelopeBytes {
		return domain.SignupGrant{}, domain.ErrUnauthenticated
	}
	var envelope struct {
		KeyID     string `json:"key_id"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	if strictSignupJSON(data, &envelope, 3) != nil || envelope.KeyID != domain.SignupProofKeyID {
		return domain.SignupGrant{}, domain.ErrUnauthenticated
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(envelope.Payload)
	if err != nil || len(payload) == 0 || len(payload) > maxSignupPayloadBytes || base64.StdEncoding.EncodeToString(payload) != envelope.Payload {
		return domain.SignupGrant{}, domain.ErrUnauthenticated
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(signature) != envelope.Signature ||
		!ed25519.Verify(v.publicKey, payload, signature) {
		return domain.SignupGrant{}, domain.ErrUnauthenticated
	}
	// Payload parsing and all storage/replay occur only after signature validation.
	var grant domain.SignupGrant
	if strictSignupJSON(payload, &grant, 15) != nil || !domain.ValidSignupIdentity(grant, subject) {
		return domain.SignupGrant{}, domain.ErrUnauthenticated
	}
	now := v.now().Unix()
	if grant.IssuedAt <= 0 || grant.IssuedAt > now+5 || grant.ExpiresAt <= now ||
		grant.ExpiresAt <= grant.IssuedAt || grant.ExpiresAt-grant.IssuedAt > 60 {
		return domain.SignupGrant{}, domain.ErrUnauthenticated
	}
	if !domain.ValidSignupBinding(grant, subject) {
		return domain.SignupGrant{}, domain.ErrSignupConflict
	}
	return grant, nil
}

// strictSignupJSON requires one object, rejects duplicate and unknown fields,
// and lets typed decoding reject non-integer timestamps and wrong field types.
func strictSignupJSON(data []byte, target any, requiredFields int) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return domain.ErrUnauthenticated
	}
	seen := make(map[string]bool)
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return domain.ErrUnauthenticated
		}
		seen[key] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return domain.ErrUnauthenticated
		}
	}
	if len(seen) != requiredFields {
		return domain.ErrUnauthenticated
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return domain.ErrUnauthenticated
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}
