package domain

import (
	"context"
	"errors"
	"strings"
)

const (
	SignupProofKeyID   = "auth-signup-v1"
	SignupIssuer       = "ms-go-auth"
	SignupAudience     = "ms-go-rbac"
	SignupPurpose      = "signup-student-provisioning-v1"
	SignupRole         = "student"
	SignupKind         = "user"
	SignupTenantID     = "00000000-0000-0000-0000-000000000000"
	SignupServiceID    = "00000000-0000-0000-0000-000000000100"
	SignupResourceKind = "global"
	SignupResourceID   = "00000000-0000-0000-0000-000000000000"
)

var ErrSignupConflict = errors.New("signup provisioning binding conflicts with existing state")

// SignupGrant is a value copy of the immutable binding returned by the proof verifier.
// Raw proof, signature and credentials must never be stored with its receipt.
type SignupGrant struct {
	Version       int    `json:"version"`
	Issuer        string `json:"issuer"`
	Audience      string `json:"audience"`
	Purpose       string `json:"purpose"`
	Subject       string `json:"subject"`
	OperationID   string `json:"operation_id"`
	PrincipalID   string `json:"principal_id"`
	Role          string `json:"role"`
	PrincipalKind string `json:"principal_kind"`
	TenantID      string `json:"tenant_id"`
	ServiceID     string `json:"service_id"`
	ResourceKind  string `json:"resource_kind"`
	ResourceID    string `json:"resource_id"`
	IssuedAt      int64  `json:"issued_at"`
	ExpiresAt     int64  `json:"expires_at"`
}

type SignupProofVerifier interface {
	VerifySignupProof(context.Context, string, []byte) (SignupGrant, error)
}

type SignupProvisioningRepository interface {
	ProvisionSignup(context.Context, SignupGrant) error
}

// ValidSignupIdentity checks the canonical Auth operation and transport identity.
// Role/scope are checked separately so an incompatible operation binding is a
// contract conflict, never an alternative grant.
func ValidSignupIdentity(g SignupGrant, subject string) bool {
	return g.Version == 1 && g.Issuer == SignupIssuer && g.Audience == SignupAudience &&
		g.Purpose == SignupPurpose && g.Subject == subject && ValidSignupSubject(subject) &&
		ValidPrincipalID(g.OperationID) && g.OperationID == strings.ToLower(g.OperationID) &&
		ValidPrincipalID(g.PrincipalID) && g.PrincipalID == strings.ToLower(g.PrincipalID)
}

// ValidSignupBinding limits this accepted authority to the canonical student flow.
func ValidSignupBinding(g SignupGrant, subject string) bool {
	return ValidSignupIdentity(g, subject) && g.Role == SignupRole && g.PrincipalKind == SignupKind && g.TenantID == SignupTenantID &&
		g.ServiceID == SignupServiceID && g.ResourceKind == SignupResourceKind && g.ResourceID == SignupResourceID
}

func ValidSignupSubject(subject string) bool {
	return subject != "" && !strings.ContainsAny(subject, "*> \t\r\n") &&
		!strings.HasPrefix(subject, ".") && !strings.HasSuffix(subject, ".") && !strings.Contains(subject, "..")
}
