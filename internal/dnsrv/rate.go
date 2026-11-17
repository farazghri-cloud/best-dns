package dnsrv

import (
	"encoding/base64"
	"strings"
	"sync"
	"time"
)

// rateLimiter is a per-source token bucket. It exists so one subscriber with a
// looping stub resolver cannot starve everyone else's queries.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	lastGC  time.Time
}

type bucket struct {
	tokens float64
	seen   time.Time
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{buckets: make(map[string]*bucket, 1024), lastGC: time.Now()}
}

// allow reports whether a source may send another query now.
func (r *rateLimiter) allow(ip string, perSecond int) bool {
	if perSecond <= 0 {
		return true
	}
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.buckets[ip]
	if !ok {
		b = &bucket{tokens: float64(perSecond), seen: now}
		r.buckets[ip] = b
	}
	// refill at perSecond tokens/sec, burst = perSecond
	elapsed := now.Sub(b.seen).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * float64(perSecond)
		if b.tokens > float64(perSecond)*2 {
			b.tokens = float64(perSecond) * 2
		}
		b.seen = now
	}
	if now.Sub(r.lastGC) > time.Minute {
		r.gcLocked(now)
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (r *rateLimiter) gcLocked(now time.Time) {
	r.lastGC = now
	for k, b := range r.buckets {
		if now.Sub(b.seen) > 5*time.Minute {
			delete(r.buckets, k)
		}
	}
}

func base64URLDecode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}
