package cache

import (
	"sync"
	"time"
)

type entry[V any] struct {
	value     V
	expiresAt time.Time
}

func (e *entry[V]) expired(now time.Time) bool {
	return !e.expiresAt.IsZero() && now.After(e.expiresAt)
}

type Cache[K comparable, V any] struct {
	mu      sync.RWMutex
	entries map[K]*entry[V]
}

func New[K comparable, V any]() *Cache[K, V] {
	return &Cache[K, V]{
		entries: make(map[K]*entry[V]),
	}
}

func (c *Cache[K, V]) Get(key K) (V, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	e, ok := c.entries[key]
	if !ok {
		var zero V
		return zero, false
	}
	if e.expired(time.Now()) {
		var zero V
		return zero, false
	}
	return e.value, true
}

func (c *Cache[K, V]) Set(key K, value V, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = time.Now().Add(ttl)
	}
	c.entries[key] = &entry[V]{
		value:     value,
		expiresAt: expiresAt,
	}
}

func (c *Cache[K, V]) Delete(key K) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

func (c *Cache[K, V]) InvalidatePrefix(prefix func(K) bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.entries {
		if prefix(k) {
			delete(c.entries, k)
		}
	}
}

func (c *Cache[K, V]) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[K]*entry[V])
}

func (c *Cache[K, V]) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
