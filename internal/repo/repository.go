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

	services        map[string]Service
	roles           map[string]Role
	rolesByKey      map[string]string
	permissions     map[string]Permission
	principalRoles  map[string]string
	rolePermissions map[string]map[string]struct{}
}

// New initialises an empty repository.
func New() *Repository {
	return &Repository{
		services:        make(map[string]Service),
		roles:           make(map[string]Role),
		rolesByKey:      make(map[string]string),
		permissions:     make(map[string]Permission),
		principalRoles:  make(map[string]string),
		rolePermissions: make(map[string]map[string]struct{}),
	}
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

// PDP contracts - not yet implemented for in-memory stub.
func (r *Repository) IsSuperAdmin(principalID string, kind model.PrincipalKind) (bool, error) {
	return false, ErrNotImplemented
}

func (r *Repository) FindMostSpecificOverride(req domainpdp.CheckRequest) (*domainpdp.OverrideMatch, error) {
	return nil, ErrNotImplemented
}

func (r *Repository) ResolveRoles(req domainpdp.CheckRequest) ([]domainpdp.RoleWithScope, error) {
	return nil, ErrNotImplemented
}

func (r *Repository) ListPermissionsForRoles(roleIDs []string) ([]domainpdp.RolePermissionItem, error) {
	return nil, ErrNotImplemented
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
