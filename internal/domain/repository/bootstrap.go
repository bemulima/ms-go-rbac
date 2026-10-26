package repository

import "context"

// OperatorBootstrap is an exact, explicit grant intent; never accepted over HTTP/NATS.
type OperatorBootstrap struct {
	RequestID    string `json:"request_id"`
	PrincipalID  string `json:"principal_id"`
	Role         string `json:"role"`
	ExpectedRole string `json:"expected_role"`
	Operator     string `json:"operator"`
	Environment  string `json:"environment"`
}
type BootstrapReceipt struct {
	OperatorBootstrap
	AppliedAt string `json:"applied_at"`
}
type OperatorBootstrapRepository interface {
	Bootstrap(context.Context, OperatorBootstrap) (BootstrapReceipt, error)
}
