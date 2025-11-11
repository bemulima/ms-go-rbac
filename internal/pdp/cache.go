package pdp

import (
	"sync"
	"time"

	"github.com/example/ms-rbac-service/internal/domain/pdp"
)

type cacheEntry struct {
	result    pdp.CheckResult
	expiresAt time.Time
}

// Cache provides a simple TTL bound cache for PDP decisions.
type Cache struct {
	ttl    time.Duration
	mu     sync.RWMutex
	values map[string]cacheEntry
}

// NewCache creates a cache with the provided TTL.
func NewCache(ttl time.Duration) *Cache {
	return &Cache{
		ttl:    ttl,
		values: make(map[string]cacheEntry),
	}
}

// Get fetches a decision by key.
func (c *Cache) Get(key string) (pdp.CheckResult, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.values[key]
	if !ok {
		return pdp.CheckResult{}, false
	}
	if time.Now().After(entry.expiresAt) {
		return pdp.CheckResult{}, false
	}
	return entry.result, true
}

// Set stores a decision result.
func (c *Cache) Set(key string, result pdp.CheckResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.values[key] = cacheEntry{result: result, expiresAt: time.Now().Add(c.ttl)}
}
