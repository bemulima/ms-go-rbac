package domain

import "errors"

var ErrNotFound = errors.New("record not found")

// ErrAmbiguousPrincipalRole indicates that a principal has multiple roles in
// the canonical default scope, so a permission decision cannot be made safely.
var ErrAmbiguousPrincipalRole = errors.New("ambiguous principal role assignment")
