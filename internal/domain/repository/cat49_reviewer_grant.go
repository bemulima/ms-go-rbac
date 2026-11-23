package repository

import "context"

// CAT49RegistrationReceipt is signed by the dedicated Auth operator.
// It is not a signup receipt or a claim supplied by a browser.
type CAT49RegistrationReceipt struct {
	Schema        string `json:"schema"`
	RunID         string `json:"run_id"`
	RequestID     string `json:"request_id"`
	PrincipalID   string `json:"principal_id"`
	AuthDatabase  string `json:"auth_database"`
	IntentDigest  string `json:"intent_digest"`
	ReceiptDigest string `json:"receipt_digest"`
	Signature     string `json:"signature"`
}

type CAT49ReviewerGrantIntent struct {
	RunID             string
	RequestID         string
	PrincipalID       string
	AuthReceiptDigest string
	Operator          string
}

type CAT49ReviewerGrantReceipt struct {
	Schema            string `json:"schema"`
	RunID             string `json:"run_id"`
	RequestID         string `json:"request_id"`
	PrincipalID       string `json:"principal_id"`
	AuthReceiptDigest string `json:"auth_receipt_digest"`
	Role              string `json:"role"`
	Operator          string `json:"operator"`
	AppliedAt         string `json:"applied_at"`
	ReceiptDigest     string `json:"receipt_digest"`
	Signature         string `json:"signature"`
}

type CAT49ReviewerGrantStore interface {
	GrantCAT49Reviewer(context.Context, CAT49ReviewerGrantIntent) (CAT49ReviewerGrantReceipt, error)
}
