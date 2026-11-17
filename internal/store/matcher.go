package store

import (
	"net"
	"sort"
	"strings"
)

// Matcher resolves a queried name to the routes that claim it.
//
// A domain entry can be written three ways:
//
//	example.com     -> example.com and every subdomain
//	*.example.com   -> subdomains only
//	=example.com    -> that exact name only
//
// Matching is suffix based and allocation free on the hot path: for
// "a.b.example.com" we look up "a.b.example.com", "b.example.com",
// "example.com" and "com" in a couple of maps.
type Matcher struct {
	self   map[string][]string // name + subdomains
	wild   map[string][]string // subdomains only
	exact  map[string][]string // exact name only
	kw     []kwRule
	routes int
}

type kwRule struct {
	needle string
	route  string
}

// NewMatcher returns an empty matcher.
func NewMatcher() *Matcher {
	return &Matcher{
		self:  make(map[string][]string, 256),
		wild:  make(map[string][]string, 128),
		exact: make(map[string][]string, 128),
	}
}

// Add registers one domain pattern for a route.
func (m *Matcher) Add(pattern, route string) {
	p := strings.ToLower(strings.TrimSpace(pattern))
	p = strings.TrimSuffix(p, ".")
	if p == "" {
		return
	}
	switch {
	case strings.HasPrefix(p, "keyword:"):
		n := strings.TrimPrefix(p, "keyword:")
		if n != "" {
			m.kw = append(m.kw, kwRule{needle: n, route: route})
		}
	case strings.HasPrefix(p, "="):
		n := strings.TrimPrefix(p, "=")
		if n != "" {
			m.exact[n] = appendUnique(m.exact[n], route)
		}
	case strings.HasPrefix(p, "*."):
		n := strings.TrimPrefix(p, "*.")
		if n != "" {
			m.wild[n] = appendUnique(m.wild[n], route)
		}
	default:
		m.self[p] = appendUnique(m.self[p], route)
	}
	m.routes++
}

// Routes returns the number of patterns registered.
func (m *Matcher) Routes() int { return m.routes }

// Match returns the route IDs claiming name (order is stable, duplicates
// removed). The caller decides whether the client owns any of them.
func (m *Matcher) Match(name string) []string {
	if m == nil {
		return nil
	}
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	if n == "" {
		return nil
	}
	var hits []string
	if ids, ok := m.exact[n]; ok {
		hits = append(hits, ids...)
	}
	// Walk every suffix boundary: "a.b.c" -> "a.b.c", "b.c", "c".
	start := 0
	first := true
	for {
		suffix := n[start:]
		if ids, ok := m.self[suffix]; ok {
			hits = append(hits, ids...)
		}
		if !first {
			if ids, ok := m.wild[suffix]; ok {
				hits = append(hits, ids...)
			}
		}
		first = false
		idx := strings.IndexByte(suffix, '.')
		if idx < 0 {
			break
		}
		start += idx + 1
	}
	for _, k := range m.kw {
		if strings.Contains(n, k.needle) {
			hits = append(hits, k.route)
		}
	}
	if len(hits) == 0 {
		return nil
	}
	return dedupe(hits)
}

func appendUnique(in []string, v string) []string {
	for _, s := range in {
		if s == v {
			return in
		}
	}
	return append(in, v)
}

func dedupe(in []string) []string {
	if len(in) < 2 {
		return in
	}
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// NormalizeDomains cleans, validates and de-duplicates a user supplied list.
// Invalid entries are dropped rather than failing the whole save.
func NormalizeDomains(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, raw := range in {
		// one entry may hold several lines pasted at once; a line that starts
		// with # is a comment and is dropped as a whole
		for _, line := range strings.Split(raw, "\n") {
			if trimmed := strings.TrimSpace(line); trimmed == "" ||
				strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
				continue
			}
			for _, token := range strings.FieldsFunc(line, func(r rune) bool {
				return r == ',' || r == ';' || r == '	' || r == ' '
			}) {
				d := normalizeDomain(token)
				if d == "" || seen[d] {
					continue
				}
				seen[d] = true
				out = append(out, d)
			}
		}
	}
	sort.Strings(out)
	return out
}

func normalizeDomain(s string) string {
	d := strings.TrimSpace(s)
	if d == "" || strings.HasPrefix(d, "#") || strings.HasPrefix(d, "//") {
		return ""
	}
	// accept full URLs pasted from a browser
	if i := strings.Index(d, "://"); i >= 0 {
		d = d[i+3:]
	}
	if i := strings.IndexAny(d, "/?#"); i >= 0 {
		d = d[:i]
	}
	if i := strings.Index(d, "@"); i >= 0 {
		d = d[i+1:]
	}
	if i := strings.Index(d, ":"); i >= 0 && !strings.Contains(d, "::") {
		d = d[:i]
	}
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimSuffix(d, ".")
	if d == "" {
		return ""
	}
	prefix := ""
	switch {
	case strings.HasPrefix(d, "keyword:"):
		kw := strings.TrimSpace(strings.TrimPrefix(d, "keyword:"))
		if kw == "" {
			return ""
		}
		return "keyword:" + kw
	case strings.HasPrefix(d, "*."):
		prefix = "*."
		d = strings.TrimPrefix(d, "*.")
	case strings.HasPrefix(d, "="):
		prefix = "="
		d = strings.TrimPrefix(d, "=")
	}
	if strings.HasPrefix(d, "www.") {
		// keep it, an operator may want only www
	}
	if !validDomain(d) {
		return ""
	}
	return prefix + d
}

func validDomain(d string) bool {
	if len(d) < 3 || len(d) > 253 {
		return false
	}
	if !strings.Contains(d, ".") {
		return false // a bare label is not a routable name
	}
	if net.ParseIP(d) != nil {
		return false // addresses are not patterns
	}
	if strings.HasPrefix(d, ".") || strings.Contains(d, "..") {
		return false
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
				continue
			}
			return false
		}
	}
	return true
}
