// Package metrics keeps the live counters the dashboard reads. Everything is
// in memory on purpose: query names are never written to disk.
package metrics

import (
	"sort"
	"sync"
	"time"
)

const ringSeconds = 90

// Usage is a per-client delta.
type Usage struct {
	Queries uint64
	Bytes   uint64
	Seen    time.Time
}

// Stats is a counter set.
type Stats struct {
	mu     sync.Mutex
	start  time.Time
	total  uint64
	routed uint64
	cached uint64
	refuse uint64
	failed uint64

	proxyOK    uint64
	proxyErr   uint64
	proxyBytes uint64

	ring     [ringSeconds]uint64
	ringSec  int64
	domains  map[string]uint64
	perClient map[string]*Usage
	limit    int
}

// New builds a counter set.
func New() *Stats {
	return &Stats{
		start:     time.Now(),
		domains:   make(map[string]uint64, 512),
		perClient: make(map[string]*Usage, 64),
		limit:     600,
	}
}

// Start returns the boot time.
func (s *Stats) Start() time.Time { return s.start }

// Uptime returns the running duration.
func (s *Stats) Uptime() time.Duration { return time.Since(s.start) }

func (s *Stats) tickLocked() {
	now := time.Now().Unix()
	if now == s.ringSec {
		return
	}
	// clear buckets we skipped over so a quiet period reads as zero
	from := s.ringSec + 1
	if s.ringSec == 0 {
		from = now
	}
	for sec := from; sec <= now; sec++ {
		s.ring[sec%ringSeconds] = 0
	}
	s.ringSec = now
}

// Query records a query outcome.
func (s *Stats) Query(srcIP, name string, routed, cached, refused bool) {
	s.mu.Lock()
	s.total++
	if routed {
		s.routed++
	}
	if cached {
		s.cached++
	}
	if refused {
		s.refuse++
	}
	s.tickLocked()
	s.ring[time.Now().Unix()%ringSeconds]++
	if s.limit > 0 && name != "" {
		s.domains[name]++
		if len(s.domains) > s.limit*2 {
			s.pruneDomainsLocked()
		}
	}
	s.mu.Unlock()
}

// Failed records an upstream failure.
func (s *Stats) Failed() {
	s.mu.Lock()
	s.failed++
	s.mu.Unlock()
}

// ProxyConn records one relayed connection and its byte counts.
func (s *Stats) ProxyConn(ok bool, bytes uint64, clientID string) {
	s.mu.Lock()
	if ok {
		s.proxyOK++
	} else {
		s.proxyErr++
	}
	s.proxyBytes += bytes
	if clientID != "" {
		u := s.perClient[clientID]
		if u == nil {
			u = &Usage{}
			s.perClient[clientID] = u
		}
		u.Bytes += bytes
		u.Seen = time.Now()
	}
	s.mu.Unlock()
}

// ClientQuery attributes one query to a client.
func (s *Stats) ClientQuery(clientID string) {
	if clientID == "" {
		return
	}
	s.mu.Lock()
	u := s.perClient[clientID]
	if u == nil {
		u = &Usage{}
		s.perClient[clientID] = u
	}
	u.Queries++
	u.Seen = time.Now()
	s.mu.Unlock()
}

// DrainUsage returns and resets per-client deltas, so the store can persist
// them in one transaction.
func (s *Stats) DrainUsage() map[string]Usage {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.perClient) == 0 {
		return nil
	}
	out := make(map[string]Usage, len(s.perClient))
	for k, v := range s.perClient {
		out[k] = *v
	}
	s.perClient = make(map[string]*Usage, 64)
	return out
}

func (s *Stats) pruneDomainsLocked() {
	type kv struct {
		k string
		v uint64
	}
	all := make([]kv, 0, len(s.domains))
	for k, v := range s.domains {
		all = append(all, kv{k, v})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].v > all[j].v })
	keep := make(map[string]uint64, s.limit)
	for i := 0; i < len(all) && i < s.limit; i++ {
		keep[all[i].k] = all[i].v
	}
	s.domains = keep
}

// DomainCount is one row of the top-domains chart.
type DomainCount struct {
	Name  string `json:"name"`
	Count uint64 `json:"count"`
}

// Snapshot is the JSON payload served to the panel.
type Snapshot struct {
	Uptime     float64       `json:"uptime_seconds"`
	Total      uint64        `json:"queries_total"`
	Routed     uint64        `json:"queries_routed"`
	Cached     uint64        `json:"queries_cached"`
	Refused    uint64        `json:"queries_refused"`
	Failed     uint64        `json:"queries_failed"`
	ProxyOK    uint64        `json:"proxy_connections"`
	ProxyErr   uint64        `json:"proxy_errors"`
	ProxyBytes uint64        `json:"proxy_bytes"`
	QPS        float64       `json:"qps"`
	Series     []uint64      `json:"series"`
	TopDomains []DomainCount `json:"top_domains"`
}

// Snapshot builds a consistent view.
func (s *Stats) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tickLocked()
	now := time.Now().Unix()
	series := make([]uint64, ringSeconds)
	var sum uint64
	for i := 0; i < ringSeconds; i++ {
		sec := now - int64(ringSeconds-1-i)
		series[i] = s.ring[sec%ringSeconds]
		sum += series[i]
	}
	top := make([]DomainCount, 0, len(s.domains))
	for k, v := range s.domains {
		top = append(top, DomainCount{Name: k, Count: v})
	}
	sort.Slice(top, func(i, j int) bool { return top[i].Count > top[j].Count })
	if len(top) > 15 {
		top = top[:15]
	}
	qps := float64(sum) / float64(ringSeconds)
	return Snapshot{
		Uptime:     time.Since(s.start).Seconds(),
		Total:      s.total,
		Routed:     s.routed,
		Cached:     s.cached,
		Refused:    s.refuse,
		Failed:     s.failed,
		ProxyOK:    s.proxyOK,
		ProxyErr:   s.proxyErr,
		ProxyBytes: s.proxyBytes,
		QPS:        qps,
		Series:     series,
		TopDomains: top,
	}
}

// CacheStats is a cache's own view.
type CacheStats struct {
	Entries int
	Hits    uint64
	Misses  uint64
	Evicted uint64
}
