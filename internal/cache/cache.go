package cache

import (
	"sync"
	"time"
)

type entry struct {
	value     string
	expiresAt time.Time
}

// Cache is a concurrency-safe in-memory key-value store with TTL expiration.
// It replaces Redis for single-replica deployments.
type Cache struct {
	mu    sync.RWMutex
	items map[string]entry
}

func New() *Cache {
	c := &Cache{items: make(map[string]entry)}
	go c.reapLoop()
	return c
}

// Set stores a key with the given TTL. A zero TTL means no expiration.
func (c *Cache) Set(key, value string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	exp := time.Time{}
	if ttl > 0 {
		exp = time.Now().Add(ttl)
	}
	c.items[key] = entry{value: value, expiresAt: exp}
}

// Get returns the value and true if the key exists and hasn't expired.
func (c *Cache) Get(key string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.items[key]
	if !ok {
		return "", false
	}
	if !e.expiresAt.IsZero() && time.Now().After(e.expiresAt) {
		return "", false
	}
	return e.value, true
}

// Del removes a key.
func (c *Cache) Del(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, key)
}

// Exists returns true if the key exists and hasn't expired.
func (c *Cache) Exists(key string) bool {
	_, ok := c.Get(key)
	return ok
}

// Incr atomically increments a counter key and returns the new value.
// If the key doesn't exist, it's created with value "1" and the given TTL.
// The TTL is only set on the first increment (when the key is created).
func (c *Cache) Incr(key string, ttl time.Duration) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.items[key]
	if !ok || (!e.expiresAt.IsZero() && time.Now().After(e.expiresAt)) {
		exp := time.Time{}
		if ttl > 0 {
			exp = time.Now().Add(ttl)
		}
		c.items[key] = entry{value: "1", expiresAt: exp}
		return 1
	}

	var count int64
	for _, ch := range e.value {
		if ch >= '0' && ch <= '9' {
			count = count*10 + int64(ch-'0')
		}
	}
	count++

	val := intToString(count)
	c.items[key] = entry{value: val, expiresAt: e.expiresAt}
	return count
}

func intToString(n int64) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 20)
	for n > 0 {
		buf = append(buf, byte('0'+n%10))
		n /= 10
	}
	// reverse
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf)
}

// reapLoop periodically removes expired entries.
func (c *Cache) reapLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for k, e := range c.items {
			if !e.expiresAt.IsZero() && now.After(e.expiresAt) {
				delete(c.items, k)
			}
		}
		c.mu.Unlock()
	}
}
