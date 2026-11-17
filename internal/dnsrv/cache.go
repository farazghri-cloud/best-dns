package dnsrv

import (
	"container/list"
	"sync"
	"time"
)

// cache is a small LRU with TTL, used for upstream answers and for the
// address records the SNI proxy needs.
type cache struct {
	mu      sync.Mutex
	ttl     time.Duration
	max     int
	items   map[string]*list.Element
	order   *list.List
	hits    uint64
	misses  uint64
	evicted uint64
}

type cacheEntry struct {
	key   string
	value []byte
	at    time.Time
	life  time.Duration
}

func newCache(max int, ttl time.Duration) *cache {
	return &cache{
		ttl:   ttl,
		max:   max,
		items: make(map[string]*list.Element, max/4),
		order: list.New(),
	}
}

func (c *cache) get(key string) ([]byte, uint32, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		c.misses++
		return nil, 0, false
	}
	ent := el.Value.(*cacheEntry)
	age := time.Since(ent.at)
	if age > ent.life {
		c.order.Remove(el)
		delete(c.items, key)
		c.misses++
		return nil, 0, false
	}
	c.order.MoveToFront(el)
	c.hits++
	return ent.value, uint32(age.Seconds()), true
}

func (c *cache) put(key string, value []byte, life time.Duration) {
	if life <= 0 {
		return
	}
	if life > c.ttl {
		life = c.ttl
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		ent := el.Value.(*cacheEntry)
		ent.value = value
		ent.at = time.Now()
		ent.life = life
		c.order.MoveToFront(el)
		return
	}
	ent := &cacheEntry{key: key, value: value, at: time.Now(), life: life}
	c.items[key] = c.order.PushFront(ent)
	for c.order.Len() > c.max {
		back := c.order.Back()
		if back == nil {
			break
		}
		c.order.Remove(back)
		delete(c.items, back.Value.(*cacheEntry).key)
		c.evicted++
	}
}

func (c *cache) flush() {
	c.mu.Lock()
	c.items = make(map[string]*list.Element, c.max/4)
	c.order.Init()
	c.mu.Unlock()
}

func (c *cache) stats() (int, uint64, uint64, uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len(), c.hits, c.misses, c.evicted
}
