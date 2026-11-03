package bridge

import "time"

// ExpireStatusCache forces the next request to re-check user status.
func (b *Bridge) ExpireStatusCache() {
	b.status.mu.Lock()
	defer b.status.mu.Unlock()
	for k, v := range b.status.entries {
		v.until = time.Time{}
		b.status.entries[k] = v
	}
}
