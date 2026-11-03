package bridge

import (
	"context"
	"sync"
	"time"

	"github.com/smeup-ergon/nexus-gh-auth/internal/nexus"
)

// Nexus' Rut Auth realm does not check a user's status: a disabled or locked
// user is still authenticated through the trusted header. The bridge
// therefore checks the status itself before asserting a user, caching the
// answer briefly so the Nexus API is not called on every request.
const statusCacheTTL = 30 * time.Second

type statusEntry struct {
	active bool
	until  time.Time
}

type statusCache struct {
	mu      sync.Mutex
	entries map[string]statusEntry
	now     func() time.Time
}

func newStatusCache() *statusCache {
	return &statusCache{entries: map[string]statusEntry{}, now: time.Now}
}

// active reports whether userID exists in Nexus and is active. Errors fail
// closed (not active) and are not cached.
func (c *statusCache) active(ctx context.Context, nx *nexus.Client, userID string) (bool, error) {
	c.mu.Lock()
	e, ok := c.entries[userID]
	c.mu.Unlock()
	if ok && c.now().Before(e.until) {
		return e.active, nil
	}
	u, err := nx.GetUser(ctx, userID)
	if err != nil {
		return false, err
	}
	active := u != nil && u.Status == nexus.StatusActive
	c.set(userID, active)
	return active, nil
}

func (c *statusCache) set(userID string, active bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	// Opportunistic cleanup keeps the map bounded by recently seen users.
	if len(c.entries) > 1000 {
		for k, v := range c.entries {
			if now.After(v.until) {
				delete(c.entries, k)
			}
		}
	}
	c.entries[userID] = statusEntry{active: active, until: now.Add(statusCacheTTL)}
}
