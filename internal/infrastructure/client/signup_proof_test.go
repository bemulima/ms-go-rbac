package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/example/ms-rbac-service/internal/domain"
)

func signupTestGrant(now int64) domain.SignupGrant {
	return domain.SignupGrant{Version: 1, Issuer: domain.SignupIssuer, Audience: domain.SignupAudience,
		Purpose: domain.SignupPurpose, Subject: "rbac.assign-role", OperationID: "00000000-0000-4000-8000-000000000911",
		PrincipalID: "00000000-0000-4000-8000-000000000901", Role: domain.SignupRole,
		PrincipalKind: domain.SignupKind, TenantID: domain.SignupTenantID, ServiceID: domain.SignupServiceID,
		ResourceKind: domain.SignupResourceKind, ResourceID: domain.SignupResourceID, IssuedAt: now, ExpiresAt: now + 60}
}

func signupTestEnvelope(private ed25519.PrivateKey, payload []byte) []byte {
	data, _ := json.Marshal(map[string]string{"key_id": domain.SignupProofKeyID,
		"payload":   base64.StdEncoding.EncodeToString(payload),
		"signature": base64.StdEncoding.EncodeToString(ed25519.Sign(private, payload))})
	return data
}

func TestSignupProofStrictBindingAndFreshness(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("cannot generate local unit key")
	}
	verifier, err := NewSignupProofVerifier(base64.StdEncoding.EncodeToString(public))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	verifier.now = func() time.Time { return time.Unix(now, 0) }
	for _, tc := range []struct {
		name   string
		change func(*domain.SignupGrant)
		want   error
	}{
		{"canonical-student", func(*domain.SignupGrant) {}, nil},
		{"five-second-skew", func(g *domain.SignupGrant) { g.IssuedAt = now + 5; g.ExpiresAt = now + 65 }, nil},
		{"issuer", func(g *domain.SignupGrant) { g.Issuer = "unknown" }, domain.ErrUnauthenticated},
		{"audience", func(g *domain.SignupGrant) { g.Audience = "other" }, domain.ErrUnauthenticated},
		{"purpose", func(g *domain.SignupGrant) { g.Purpose = "other" }, domain.ErrUnauthenticated},
		{"version", func(g *domain.SignupGrant) { g.Version = 2 }, domain.ErrUnauthenticated},
		{"subject", func(g *domain.SignupGrant) { g.Subject = "other" }, domain.ErrUnauthenticated},
		{"role", func(g *domain.SignupGrant) { g.Role = "invalid" }, domain.ErrSignupConflict},
		{"kind", func(g *domain.SignupGrant) { g.PrincipalKind = "invalid" }, domain.ErrSignupConflict},
		{"tenant", func(g *domain.SignupGrant) { g.TenantID = g.PrincipalID }, domain.ErrSignupConflict},
		{"service", func(g *domain.SignupGrant) { g.ServiceID = g.PrincipalID }, domain.ErrSignupConflict},
		{"resource-kind", func(g *domain.SignupGrant) { g.ResourceKind = "other" }, domain.ErrSignupConflict},
		{"resource", func(g *domain.SignupGrant) { g.ResourceID = g.PrincipalID }, domain.ErrSignupConflict},
		{"nil-operation", func(g *domain.SignupGrant) { g.OperationID = domain.SignupTenantID }, domain.ErrUnauthenticated},
		{"nil-principal", func(g *domain.SignupGrant) { g.PrincipalID = domain.SignupTenantID }, domain.ErrUnauthenticated},
		{"noncanonical-principal", func(g *domain.SignupGrant) { g.PrincipalID = "00000000-0000-4000-8000-000000000A01" }, domain.ErrUnauthenticated},
		{"malformed-operation", func(g *domain.SignupGrant) { g.OperationID = "operation" }, domain.ErrUnauthenticated},
		{"expired", func(g *domain.SignupGrant) { g.IssuedAt = now - 60; g.ExpiresAt = now }, domain.ErrUnauthenticated},
		{"long-lifetime", func(g *domain.SignupGrant) { g.ExpiresAt = now + 61 }, domain.ErrUnauthenticated},
		{"future", func(g *domain.SignupGrant) { g.IssuedAt = now + 6; g.ExpiresAt = now + 60 }, domain.ErrUnauthenticated},
		{"reversed-time", func(g *domain.SignupGrant) { g.IssuedAt = now + 1; g.ExpiresAt = now + 1 }, domain.ErrUnauthenticated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			grant := signupTestGrant(now)
			tc.change(&grant)
			payload, _ := json.Marshal(grant)
			got, err := verifier.VerifySignupProof(context.Background(), "rbac.assign-role", signupTestEnvelope(private, payload))
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v got %v", tc.want, err)
			}
			if tc.want == nil && got != grant {
				t.Fatal("verified immutable binding changed")
			}
			if tc.want != nil && got != (domain.SignupGrant{}) {
				t.Fatal("denial returned a grant")
			}
		})
	}
	grant := signupTestGrant(now)
	grant.Subject = "isolated.signup.assign"
	payload, _ := json.Marshal(grant)
	if _, err := verifier.VerifySignupProof(context.Background(), grant.Subject, signupTestEnvelope(private, payload)); err != nil {
		t.Fatal("concrete signed subject rejected")
	}
}

func TestSignupProofRejectsUnsignedMalformedAndUntrustedData(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("cannot generate local unit key")
	}
	_, untrusted, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("cannot generate local unit key")
	}
	verifier, err := NewSignupProofVerifier(base64.StdEncoding.EncodeToString(public))
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(signupTestGrant(time.Now().Unix()))
	valid := signupTestEnvelope(private, payload)
	duplicate := strings.Replace(string(payload), `"version":1`, `"version":1,"version":1`, 1)
	unknown := strings.Replace(string(payload), `"version":1`, `"unknown":true,"version":1`, 1)
	null := strings.Replace(string(payload), `"version":1`, `"version":null`, 1)
	fraction := strings.Replace(string(payload), `"version":1`, `"version":1.5`, 1)
	for name, data := range map[string][]byte{
		"missing": nil, "unsigned-student": []byte(`{"user_id":"00000000-0000-4000-8000-000000000901","role":"student","caller":"auth"}`),
		"untrusted-key":      signupTestEnvelope(untrusted, payload),
		"duplicate-payload":  signupTestEnvelope(private, []byte(duplicate)),
		"unknown-payload":    signupTestEnvelope(private, []byte(unknown)),
		"null-payload-field": signupTestEnvelope(private, []byte(null)),
		"missing-role":       signupTestEnvelope(private, []byte(strings.Replace(string(payload), `"role":"student",`, "", 1))),
		"missing-scope":      signupTestEnvelope(private, []byte(strings.Replace(string(payload), `"resource_kind":"global",`, "", 1))),
		"noninteger":         signupTestEnvelope(private, []byte(fraction)),
		"trailing-payload":   signupTestEnvelope(private, append(append([]byte{}, payload...), []byte(`{}`)...)),
		"oversized-payload":  signupTestEnvelope(private, []byte(strings.Repeat(" ", maxSignupPayloadBytes+1))),
		"oversized-envelope": []byte(strings.Repeat(" ", maxSignupEnvelopeBytes+1)),
		"unknown-envelope":   []byte(strings.Replace(string(valid), `"key_id":`, `"unknown":true,"key_id":`, 1)),
		"duplicate-envelope": []byte(strings.Replace(string(valid), `"key_id":`, `"key_id":"auth-signup-v1","key_id":`, 1)),
		"unknown-key-id":     []byte(strings.Replace(string(valid), domain.SignupProofKeyID, "unknown", 1)),
		"malformed-envelope": []byte(`{"key_id":"auth-signup-v1","payload":"!","signature":"!"}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := verifier.VerifySignupProof(context.Background(), "rbac.assign-role", data); !errors.Is(err, domain.ErrUnauthenticated) {
				t.Fatal("invalid canonical provisioning proof was accepted")
			}
		})
	}
	if _, err := verifier.VerifySignupProof(context.Background(), "different.subject", valid); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatal("subject binding bypass")
	}
	missing, _ := NewSignupProofVerifier("")
	if _, err := missing.VerifySignupProof(context.Background(), "rbac.assign-role", valid); !errors.Is(err, domain.ErrAuthorityUnavailable) {
		t.Fatal("missing key did not fail closed")
	}
	for _, key := range []string{"invalid", base64.StdEncoding.EncodeToString([]byte("short")), base64.StdEncoding.EncodeToString(public) + "\n"} {
		if _, err := NewSignupProofVerifier(key); err == nil {
			t.Fatal("invalid public key configuration accepted")
		}
	}
}
