package pdp

import (
	"context"
	"errors"
	"sort"

	"github.com/example/ms-rbac-service/internal/domain/model"
	domainpdp "github.com/example/ms-rbac-service/internal/domain/pdp"
)

// Engine evaluates authorisation requests using repository backed data.
type Engine struct {
	repo domainpdp.Repository
}

// NewEngine constructs a new Engine instance.
func NewEngine(repo domainpdp.Repository) *Engine {
	return &Engine{repo: repo}
}

// Check executes a single PDP decision.
func (e *Engine) Check(ctx context.Context, req domainpdp.CheckRequest) (domainpdp.CheckResult, error) {
	// Rule 1: superadmin
	isSuper, err := e.repo.GetByPrincipal(req.PrincipalID, req.PrincipalKind)
	if err != nil {
		return domainpdp.CheckResult{}, err
	}
	if isSuper {
		return domainpdp.CheckResult{Allow: true, Decision: "superadmin", RoleKeys: nil, CorrelationID: req.CorrelationID}, nil
	}

	// Rule 2: overrides with specificity ordering
	override, err := e.repo.GetByRequest(req)
	if err != nil {
		return domainpdp.CheckResult{}, err
	}
	if override != nil {
		allow := override.Effect == model.OverrideEffectAllow
		decision := "override"
		if !allow {
			decision = "deny"
		}
		return domainpdp.CheckResult{Allow: allow, Decision: decision, CorrelationID: req.CorrelationID}, nil
	}

	roles, err := e.repo.List(req)
	if err != nil {
		return domainpdp.CheckResult{}, err
	}
	if len(roles) == 0 {
		return domainpdp.CheckResult{Allow: false, Decision: "deny", CorrelationID: req.CorrelationID}, nil
	}

	roleIDs := make([]string, 0, len(roles))
	roleKeys := make([]string, 0, len(roles))
	for _, r := range roles {
		roleIDs = append(roleIDs, r.RoleID)
		roleKeys = append(roleKeys, r.RoleKey)
	}

	perms, err := e.repo.ListByRoleIDs(roleIDs)
	if err != nil {
		return domainpdp.CheckResult{}, err
	}

	if matchPermission(perms, req.Action, req.ResourceKind, req.ResourceID, req.ServiceID, roles) {
		return domainpdp.CheckResult{Allow: true, Decision: "role", RoleKeys: roleKeys, CorrelationID: req.CorrelationID}, nil
	}
	return domainpdp.CheckResult{Allow: false, Decision: "deny", RoleKeys: roleKeys, CorrelationID: req.CorrelationID}, nil
}

func matchPermission(perms []domainpdp.RolePermissionItem, action, resourceKind string, resourceID *string, serviceID *string, roles []domainpdp.RoleWithScope) bool {
	if len(perms) == 0 {
		return false
	}

	roleScopes := map[string]domainpdp.OverrideScope{}
	roleServiceLimit := map[string][]string{}
	for _, r := range roles {
		roleScopes[r.RoleID] = r.Scope
		if len(r.ServiceIDs) > 0 {
			roleServiceLimit[r.RoleID] = r.ServiceIDs
		}
	}

	// pre-sort service limits for binary search
	for _, ids := range roleServiceLimit {
		sort.Strings(ids)
	}

	for _, p := range perms {
		scope := roleScopes[p.RoleID]
		if !scopeMatches(scope, serviceID, resourceKind, resourceID) {
			continue
		}
		if ids, ok := roleServiceLimit[p.RoleID]; ok {
			if serviceID == nil {
				continue
			}
			idx := sort.SearchStrings(ids, *serviceID)
			if idx >= len(ids) || ids[idx] != *serviceID {
				continue
			}
		}
		if p.Action != action {
			continue
		}
		if p.ResourceKind != resourceKind && p.ResourceKind != "*" {
			continue
		}
		if p.ResourceID != nil {
			if resourceID == nil || *p.ResourceID != *resourceID {
				continue
			}
		}
		return true
	}
	return false
}

func scopeMatches(scope domainpdp.OverrideScope, serviceID *string, resourceKind string, resourceID *string) bool {
	if scope.ServiceID != nil {
		if serviceID == nil || *scope.ServiceID != *serviceID {
			return false
		}
	}
	if scope.ResourceKind != nil {
		if *scope.ResourceKind != resourceKind {
			return false
		}
	}
	if scope.ResourceID != nil {
		if resourceID == nil || *scope.ResourceID != *resourceID {
			return false
		}
	}
	return true
}

var ErrRepositoryNotImplemented = errors.New("repository method not implemented")
