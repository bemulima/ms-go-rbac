package repo

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/example/ms-rbac-service/internal/domain/model"
	domainpdp "github.com/example/ms-rbac-service/internal/domain/pdp"
)

// Repository provides in-memory storage for RBAC entities.
type Repository struct {
	mu sync.RWMutex

	services           map[string]Service
	roles              map[string]Role
	rolesByKey         map[string]string
	permissions        map[string]Permission
	principalRoles     map[string]string
	rolePermissions    map[string]map[string]struct{}
	superadminPrincipals map[string]model.PrincipalKind // key: principalID
	principalOverrides    []PrincipalOverrideStub       // for PDP
	principalRoleScopes   map[string]PrincipalRoleScope // key: principalID+roleID
}

type PrincipalOverrideStub struct {
	PrincipalID   string
	PrincipalKind model.PrincipalKind
	PermissionID  string
	Effect        model.OverrideEffect
	TenantID      *string
	ServiceID     *string
	ResourceKind  *string
	ResourceID    *string
}

type PrincipalRoleScope struct {
	PrincipalID   string
	PrincipalKind model.PrincipalKind
	RoleID        string
	TenantID      *string
	ServiceID     *string
	ResourceKind  *string
	ResourceID    *string
	ServiceIDs    []string
}

var defaultRoles = []struct {
	Key   string
	Title string
}{
	{Key: "admin", Title: "Admin"},
	{Key: "moderator", Title: "Moderator"},
	{Key: "teacher", Title: "Teacher"},
	{Key: "student", Title: "Student"},
	{Key: "user", Title: "User"},
	{Key: "guest", Title: "Guest"},
}

// New initialises an empty repository.
func New() *Repository {
	r := &Repository{
		services:             make(map[string]Service),
		roles:                make(map[string]Role),
		rolesByKey:           make(map[string]string),
		permissions:          make(map[string]Permission),
		principalRoles:       make(map[string]string),
		rolePermissions:      make(map[string]map[string]struct{}),
		superadminPrincipals: make(map[string]model.PrincipalKind),
		principalOverrides:    make([]PrincipalOverrideStub, 0),
		principalRoleScopes:   make(map[string]PrincipalRoleScope),
	}
	r.seedDefaultRoles()
	return r
}

func (r *Repository) now() time.Time {
	return time.Now().UTC()
}

func (r *Repository) CreateService(ctx context.Context, service *Service) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	service.ID = generateID()
	service.CreatedAt = r.now()
	service.UpdatedAt = service.CreatedAt
	r.services[service.ID] = *service
	return nil
}

func (r *Repository) UpdateService(ctx context.Context, id string, title string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	svc, ok := r.services[id]
	if !ok {
		return ErrNotFound
	}
	svc.Title = title
	svc.UpdatedAt = r.now()
	r.services[id] = svc
	return nil
}

func (r *Repository) GetService(ctx context.Context, id string) (*Service, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	svc, ok := r.services[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := svc
	return &cp, nil
}

func (r *Repository) ListServices(ctx context.Context, offset, limit int) ([]Service, int64, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	items := make([]Service, 0, len(r.services))
	for _, svc := range r.services {
		items = append(items, svc)
	}
	total := int64(len(items))
	start := clamp(offset, 0, len(items))
	end := clamp(offset+limit, start, len(items))
	return items[start:end], total, nil
}

func (r *Repository) CreateRole(ctx context.Context, role *Role) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	role.ID = generateID()
	role.CreatedAt = r.now()
	role.UpdatedAt = role.CreatedAt
	r.roles[role.ID] = *role
	r.rolesByKey[role.Key] = role.ID
	return nil
}

func (r *Repository) UpdateRole(ctx context.Context, id string, title string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	rl, ok := r.roles[id]
	if !ok {
		return ErrNotFound
	}
	rl.Title = title
	rl.UpdatedAt = r.now()
	r.roles[id] = rl
	return nil
}

func (r *Repository) GetRole(ctx context.Context, id string) (*Role, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rl, ok := r.roles[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := rl
	return &cp, nil
}

func (r *Repository) ListRoles(ctx context.Context, offset, limit int) ([]Role, int64, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	items := make([]Role, 0, len(r.roles))
	for _, rl := range r.roles {
		items = append(items, rl)
	}
	total := int64(len(items))
	start := clamp(offset, 0, len(items))
	end := clamp(offset+limit, start, len(items))
	return items[start:end], total, nil
}

func (r *Repository) CreatePermission(ctx context.Context, p *Permission) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	p.ID = generateID()
	p.CreatedAt = r.now()
	p.UpdatedAt = p.CreatedAt
	r.permissions[p.ID] = *p
	return nil
}

func (r *Repository) UpdatePermission(ctx context.Context, id string, attrs map[string]interface{}) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	item, ok := r.permissions[id]
	if !ok {
		return ErrNotFound
	}
	if v, ok := attrs["action"].(string); ok {
		item.Action = v
	}
	if v, ok := attrs["resource_kind"].(string); ok {
		item.ResourceKind = v
	}
	item.UpdatedAt = r.now()
	r.permissions[id] = item
	return nil
}

func (r *Repository) GetPermission(ctx context.Context, id string) (*Permission, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	item, ok := r.permissions[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := item
	return &cp, nil
}

func (r *Repository) ListPermissions(ctx context.Context, offset, limit int) ([]Permission, int64, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	items := make([]Permission, 0, len(r.permissions))
	for _, p := range r.permissions {
		items = append(items, p)
	}
	total := int64(len(items))
	start := clamp(offset, 0, len(items))
	end := clamp(offset+limit, start, len(items))
	return items[start:end], total, nil
}

// Principal role helpers.
func (r *Repository) AssignPrincipalRole(ctx context.Context, principalID, role string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.rolesByKey[role]; !ok {
		return ErrNotFound
	}
	r.principalRoles[principalID] = role
	return nil
}

func (r *Repository) GetPrincipalRole(ctx context.Context, principalID string) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.principalRoles[principalID], nil
}

// Role permission helpers.
func (r *Repository) AssignPermissionToRole(ctx context.Context, roleKey, permissionID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.rolesByKey[roleKey]; !ok {
		return ErrNotFound
	}
	if _, ok := r.permissions[permissionID]; !ok {
		return ErrNotFound
	}
	if _, ok := r.rolePermissions[roleKey]; !ok {
		r.rolePermissions[roleKey] = make(map[string]struct{})
	}
	r.rolePermissions[roleKey][permissionID] = struct{}{}
	return nil
}

func (r *Repository) ListPermissionsForRole(ctx context.Context, roleKey string) ([]Permission, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids, ok := r.rolePermissions[roleKey]
	if !ok || len(ids) == 0 {
		return nil, nil
	}
	perms := make([]Permission, 0, len(ids))
	for id := range ids {
		if perm, ok := r.permissions[id]; ok {
			perms = append(perms, perm)
		}
	}
	sort.Slice(perms, func(i, j int) bool {
		return perms[i].ID < perms[j].ID
	})
	return perms, nil
}

// PDP contracts implementation for in-memory repository.

// IsSuperAdmin checks if principal is a superadmin.
func (r *Repository) IsSuperAdmin(principalID string, kind model.PrincipalKind) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	storedKind, exists := r.superadminPrincipals[principalID]
	if !exists {
		return false, nil
	}
	return storedKind == kind, nil
}

// FindMostSpecificOverride finds the most specific override matching the request.
// Specificity order: tenant_id > service_id > resource_kind > resource_id
func (r *Repository) FindMostSpecificOverride(req domainpdp.CheckRequest) (*domainpdp.OverrideMatch, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var bestMatch *PrincipalOverrideStub
	bestScore := -1

	for _, override := range r.principalOverrides {
		if override.PrincipalID != req.PrincipalID || override.PrincipalKind != req.PrincipalKind {
			continue
		}
		// Check if override matches request scope
		if !r.overrideMatches(override, req) {
			continue
		}
		// Calculate specificity score (higher = more specific)
		score := r.calculateSpecificity(override)
		if score > bestScore {
			bestScore = score
			bestMatch = &override
		}
	}

	if bestMatch == nil {
		return nil, nil
	}

	return &domainpdp.OverrideMatch{
		Effect:       bestMatch.Effect,
		PermissionID: bestMatch.PermissionID,
		Scope: domainpdp.OverrideScope{
			TenantID:     bestMatch.TenantID,
			ServiceID:    bestMatch.ServiceID,
			ResourceKind: bestMatch.ResourceKind,
			ResourceID:   bestMatch.ResourceID,
		},
	}, nil
}

// ResolveRoles returns all roles for a principal with their scopes.
func (r *Repository) ResolveRoles(req domainpdp.CheckRequest) ([]domainpdp.RoleWithScope, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []domainpdp.RoleWithScope
	key := req.PrincipalID + ":" + string(req.PrincipalKind)

	// Check simple role assignment (no scope)
	if roleKey, ok := r.principalRoles[key]; ok {
		if roleID, ok := r.rolesByKey[roleKey]; ok {
			if role, ok := r.roles[roleID]; ok {
				result = append(result, domainpdp.RoleWithScope{
					RoleID:  role.ID,
					RoleKey: role.Key,
					Scope:   domainpdp.OverrideScope{},
				})
			}
		}
	}

	// Check scoped roles
	for _, scope := range r.principalRoleScopes {
		if scope.PrincipalID != req.PrincipalID || scope.PrincipalKind != req.PrincipalKind {
			continue
		}
		if !r.scopeMatchesRequest(scope, req) {
			continue
		}
		if role, ok := r.roles[scope.RoleID]; ok {
			result = append(result, domainpdp.RoleWithScope{
				RoleID:  role.ID,
				RoleKey: role.Key,
				Scope: domainpdp.OverrideScope{
					TenantID:     scope.TenantID,
					ServiceID:    scope.ServiceID,
					ResourceKind: scope.ResourceKind,
					ResourceID:   scope.ResourceID,
				},
				ServiceIDs: scope.ServiceIDs,
			})
		}
	}

	return result, nil
}

// ListPermissionsForRoles returns all permissions for given role IDs.
func (r *Repository) ListPermissionsForRoles(roleIDs []string) ([]domainpdp.RolePermissionItem, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []domainpdp.RolePermissionItem
	roleIDSet := make(map[string]bool)
	for _, id := range roleIDs {
		roleIDSet[id] = true
	}

	for roleID, permIDs := range r.rolePermissions {
		if !roleIDSet[roleID] {
			continue
		}
		role, ok := r.roles[roleID]
		if !ok {
			continue
		}
		for permID := range permIDs {
			perm, ok := r.permissions[permID]
			if !ok {
				continue
			}
			result = append(result, domainpdp.RolePermissionItem{
				RoleID:       role.ID,
				RoleKey:      role.Key,
				PermissionID: perm.ID,
				Action:       perm.Action,
				ResourceKind: perm.ResourceKind,
				ResourceID:   nil, // In-memory doesn't track resource_id per permission
			})
		}
	}

	return result, nil
}

// Helper methods

func (r *Repository) overrideMatches(override PrincipalOverrideStub, req domainpdp.CheckRequest) bool {
	// Check if override's permission matches request
	perm, ok := r.permissions[override.PermissionID]
	if !ok {
		return false
	}
	if perm.Action != req.Action || perm.ResourceKind != req.ResourceKind {
		return false
	}
	// Check scope matching
	return r.scopeMatchesOverride(override, req)
}

func (r *Repository) scopeMatchesOverride(override PrincipalOverrideStub, req domainpdp.CheckRequest) bool {
	if override.TenantID != nil {
		if req.TenantID == nil || *override.TenantID != *req.TenantID {
			return false
		}
	}
	if override.ServiceID != nil {
		if req.ServiceID == nil || *override.ServiceID != *req.ServiceID {
			return false
		}
	}
	if override.ResourceKind != nil {
		if *override.ResourceKind != req.ResourceKind {
			return false
		}
	}
	if override.ResourceID != nil {
		if req.ResourceID == nil || *override.ResourceID != *req.ResourceID {
			return false
		}
	}
	return true
}

func (r *Repository) scopeMatchesRequest(scope PrincipalRoleScope, req domainpdp.CheckRequest) bool {
	if scope.TenantID != nil {
		if req.TenantID == nil || *scope.TenantID != *req.TenantID {
			return false
		}
	}
	if scope.ServiceID != nil {
		if req.ServiceID == nil || *scope.ServiceID != *req.ServiceID {
			return false
		}
	}
	if scope.ResourceKind != nil {
		if *scope.ResourceKind != req.ResourceKind {
			return false
		}
	}
	if scope.ResourceID != nil {
		if req.ResourceID == nil || *scope.ResourceID != *req.ResourceID {
			return false
		}
	}
	return true
}

func (r *Repository) calculateSpecificity(override PrincipalOverrideStub) int {
	score := 0
	if override.TenantID != nil {
		score += 1000
	}
	if override.ServiceID != nil {
		score += 100
	}
	if override.ResourceKind != nil {
		score += 10
	}
	if override.ResourceID != nil {
		score += 1
	}
	return score
}

// AddSuperadmin adds a principal to superadmin list (helper for testing/setup).
func (r *Repository) AddSuperadmin(principalID string, kind model.PrincipalKind) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.superadminPrincipals[principalID] = kind
}

var (
	ErrNotFound       = errors.New("record not found")
	ErrNotImplemented = errors.New("not implemented")
)

func clamp(v, min, max int) int {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func generateID() string {
	return time.Now().UTC().Format("20060102150405.000000000")
}

func (r *Repository) seedDefaultRoles() {
	now := r.now()
	for _, item := range defaultRoles {
		id := generateID()
		r.roles[id] = Role{
			ID:    id,
			Key:   item.Key,
			Title: item.Title,
			BaseModel: BaseModel{
				CreatedAt: now,
				UpdatedAt: now,
			},
		}
		r.rolesByKey[item.Key] = id
	}
}
