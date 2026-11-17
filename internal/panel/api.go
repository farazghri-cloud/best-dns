package panel

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/farazghri-cloud/best-dns/internal/store"
)

/* ── read ──────────────────────────────────────────────── */

func (p *Panel) apiState(w http.ResponseWriter, r *http.Request) {
	snap := p.store.Snapshot()
	writeJSON(w, 200, map[string]any{
		"settings": snap.Settings,
		"routes":   p.store.Routes(),
		"clients":  p.store.Clients(),
		"meta": map[string]any{
			"version":     p.version,
			"dns_ip":      p.dns.PublicIP(),
			"proxy_ports": p.proxy.Ports(),
			"title":       p.title(),
			"temporary":   snap.PasswordIs,
			"started_at":  p.started,
		},
	})
}

func (p *Panel) apiStats(w http.ResponseWriter, r *http.Request) {
	snap := p.stats.Snapshot()
	entries, hits, misses, evicted := p.dns.CacheStats()
	writeJSON(w, 200, map[string]any{
		"uptime_seconds":   snap.Uptime,
		"queries_total":    snap.Total,
		"queries_routed":   snap.Routed,
		"queries_cached":   snap.Cached,
		"queries_refused":  snap.Refused,
		"queries_failed":   snap.Failed,
		"qps":              snap.QPS,
		"series":           snap.Series,
		"top_domains":      snap.TopDomains,
		"proxy_connections": snap.ProxyOK,
		"proxy_errors":     snap.ProxyErr,
		"proxy_bytes":      snap.ProxyBytes,
		"proxy_active":     p.proxy.Active(),
		"cache_entries":    entries,
		"cache_hits":       hits,
		"cache_misses":     misses,
		"cache_evicted":    evicted,
	})
}

/* ── routes ────────────────────────────────────────────── */

type routePayload struct {
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
	Public  *bool    `json:"public"`
	Enabled *bool    `json:"enabled"`
	Color   string   `json:"color"`
	Note    string   `json:"note"`
}

func (r routePayload) apply(base store.Route) store.Route {
	base.Name = strings.TrimSpace(r.Name)
	base.Domains = r.Domains
	base.Color = strings.TrimSpace(r.Color)
	base.Note = strings.TrimSpace(r.Note)
	if r.Public != nil {
		base.Public = *r.Public
	}
	if r.Enabled != nil {
		base.Enabled = *r.Enabled
	}
	return base
}

func (p *Panel) apiRouteCreate(w http.ResponseWriter, r *http.Request) {
	var body routePayload
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "داده‌های ارسالی نامعتبر است"})
		return
	}
	route := routePayload{}.apply(store.Route{Public: true, Enabled: true})
	route = body.apply(route)
	if len(route.Domains) == 0 {
		writeJSON(w, 400, map[string]string{"error": "حداقل یک دامنه لازم است"})
		return
	}
	created, err := p.store.CreateRoute(route)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	p.log.Info("route created", "name", created.Name, "domains", len(created.Domains))
	writeJSON(w, 201, created)
}

func (p *Panel) apiRouteUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	cur, err := p.store.Route(id)
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": "مسیر پیدا نشد"})
		return
	}
	var body routePayload
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "داده‌های ارسالی نامعتبر است"})
		return
	}
	updated, err := p.store.UpdateRoute(id, body.apply(cur))
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, updated)
}

func (p *Panel) apiRouteDelete(w http.ResponseWriter, r *http.Request) {
	if err := p.store.DeleteRoute(r.PathValue("id")); err != nil {
		writeJSON(w, 404, map[string]string{"error": "مسیر پیدا نشد"})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

/* ── clients ───────────────────────────────────────────── */

type clientPayload struct {
	Name       string     `json:"name"`
	IPs        []string   `json:"ips"`
	RouteIDs   []string   `json:"route_ids"`
	Enabled    *bool      `json:"enabled"`
	ExpiresAt  *time.Time `json:"expires_at"`
	QuotaBytes uint64     `json:"quota_bytes"`
	Note       string     `json:"note"`
}

func (c clientPayload) apply(base store.Client) store.Client {
	base.Name = strings.TrimSpace(c.Name)
	base.IPs = c.IPs
	base.RouteIDs = c.RouteIDs
	base.ExpiresAt = c.ExpiresAt
	base.QuotaBytes = c.QuotaBytes
	base.Note = strings.TrimSpace(c.Note)
	if c.Enabled != nil {
		base.Enabled = *c.Enabled
	}
	return base
}

func (p *Panel) apiClientCreate(w http.ResponseWriter, r *http.Request) {
	var body clientPayload
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "داده‌های ارسالی نامعتبر است"})
		return
	}
	client := body.apply(store.Client{Enabled: true})
	if client.Name == "" {
		writeJSON(w, 400, map[string]string{"error": "نام کلاینت لازم است"})
		return
	}
	created, err := p.store.CreateClient(client)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	p.log.Info("client created", "name", created.Name, "routes", len(created.RouteIDs))
	writeJSON(w, 201, created)
}

func (p *Panel) apiClientUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	cur, err := p.store.Client(id)
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": "کلاینت پیدا نشد"})
		return
	}
	var body clientPayload
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "داده‌های ارسالی نامعتبر است"})
		return
	}
	updated, err := p.store.UpdateClient(id, body.apply(cur))
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, updated)
}

func (p *Panel) apiClientDelete(w http.ResponseWriter, r *http.Request) {
	if err := p.store.DeleteClient(r.PathValue("id")); err != nil {
		writeJSON(w, 404, map[string]string{"error": "کلاینت پیدا نشد"})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (p *Panel) apiClientRotate(w http.ResponseWriter, r *http.Request) {
	c, err := p.store.RotateToken(r.PathValue("id"))
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": "کلاینت پیدا نشد"})
		return
	}
	writeJSON(w, 200, c)
}

func (p *Panel) apiClientReset(w http.ResponseWriter, r *http.Request) {
	c, err := p.store.ResetUsage(r.PathValue("id"))
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": "کلاینت پیدا نشد"})
		return
	}
	writeJSON(w, 200, c)
}

/* ── settings ──────────────────────────────────────────── */

func (p *Panel) apiSettings(w http.ResponseWriter, r *http.Request) {
	var body store.Settings
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "داده‌های ارسالی نامعتبر است"})
		return
	}
	body.ProxyPorts = normalizePorts(body.ProxyPorts)
	if len(body.ProxyPorts) == 0 {
		writeJSON(w, 400, map[string]string{"error": "حداقل یک پورت رله لازم است"})
		return
	}
	for _, port := range body.ProxyPorts {
		if port == 53 {
			writeJSON(w, 400, map[string]string{"error": "پورت ۵۳ متعلق به خود DNS است"})
			return
		}
	}
	ups, err := normalizeUpstreams(body.Upstreams)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	body.Upstreams = ups
	if body.ProxyIP != "" && net.ParseIP(strings.TrimSpace(body.ProxyIP)) == nil {
		writeJSON(w, 400, map[string]string{"error": "آدرس IP عمومی معتبر نیست"})
		return
	}
	if body.DoHPort != "" && !strings.HasPrefix(body.DoHPort, ":") {
		body.DoHPort = ":" + body.DoHPort
	}
	if body.CacheTTL < 0 || body.CacheTTL > 86400 {
		body.CacheTTL = 300
	}
	if body.RoutedTTL < 5 || body.RoutedTTL > 3600 {
		body.RoutedTTL = 60
	}
	if body.MaxConns < 16 {
		body.MaxConns = 16
	}
	if body.ProxyTimeout < 2 {
		body.ProxyTimeout = 10
	}
	if len(body.PanelTitle) > 40 {
		body.PanelTitle = body.PanelTitle[:40]
	}

	previous := p.store.Settings()
	saved, err := p.store.UpdateSettings(func(s *store.Settings) error {
		*s = body
		return nil
	})
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	// live-apply what can be applied without a restart
	if saved.ProxyIP != "" {
		p.dns.SetPublicIP(strings.TrimSpace(saved.ProxyIP))
	} else {
		p.dns.DetectPublicIP()
	}
	if err := p.proxy.Reload(saved.ProxyPorts); err != nil {
		p.log.Error("proxy reload failed", "err", err)
	}
	restart := previous.DoHPort != saved.DoHPort
	writeJSON(w, 200, map[string]any{"settings": saved, "restart": restart})
}

func normalizePorts(in []int) []int {
	seen := map[int]bool{}
	out := make([]int, 0, len(in))
	for _, port := range in {
		if port <= 0 || port > 65535 || seen[port] {
			continue
		}
		seen[port] = true
		out = append(out, port)
	}
	return out
}

func normalizeUpstreams(in []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, raw := range in {
		addr := strings.TrimSpace(raw)
		if addr == "" {
			continue
		}
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
			port = "53"
		}
		if net.ParseIP(host) == nil {
			if _, lerr := net.LookupHost(host); lerr != nil {
				return nil, fmt.Errorf("آدرس بالادست %q معتبر نیست", raw)
			}
		}
		pn, err := strconv.Atoi(port)
		if err != nil || pn <= 0 || pn > 65535 {
			return nil, fmt.Errorf("پورت بالادست %q معتبر نیست", raw)
		}
		full := net.JoinHostPort(host, port)
		if seen[full] {
			continue
		}
		seen[full] = true
		out = append(out, full)
	}
	if len(out) == 0 {
		return nil, errors.New("حداقل یک DNS بالادست لازم است")
	}
	return out, nil
}

/* ── password / cache / backup ─────────────────────────── */

func (p *Panel) apiPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Current string `json:"current"`
		Next    string `json:"next"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "درخواست نامعتبر"})
		return
	}
	if !p.store.VerifyPassword(body.Current) {
		writeJSON(w, 400, map[string]string{"error": "رمز فعلی اشتباه است"})
		return
	}
	if len(body.Next) < 8 {
		writeJSON(w, 400, map[string]string{"error": "رمز جدید باید حداقل ۸ کاراکتر باشد"})
		return
	}
	if err := p.store.SetPassword(body.Next, false); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	p.newSession(w, r)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (p *Panel) apiFlush(w http.ResponseWriter, r *http.Request) {
	p.dns.FlushCache()
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (p *Panel) apiBackup(w http.ResponseWriter, r *http.Request) {
	snap := p.store.Snapshot()
	buf, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=\"bestdns-backup-%s.json\"", time.Now().Format("2006-01-02-1504")))
	_, _ = w.Write(buf)
}

func (p *Panel) apiRestore(w http.ResponseWriter, r *http.Request) {
	var doc store.State
	if err := decodeJSON(r, &doc); err != nil {
		writeJSON(w, 400, map[string]string{"error": "فایل پشتیبان معتبر نیست"})
		return
	}
	if doc.Settings.Upstreams == nil {
		writeJSON(w, 400, map[string]string{"error": "فایل پشتیبان ساختار درستی ندارد"})
		return
	}
	// never let a restored file replace the live credentials
	cur := p.store.Snapshot()
	doc.AdminSalt = cur.AdminSalt
	doc.AdminHash = cur.AdminHash
	doc.SessionKey = cur.SessionKey
	doc.PasswordIs = cur.PasswordIs
	if err := p.store.ReplaceState(doc); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if err := p.proxy.Reload(p.store.Settings().ProxyPorts); err != nil {
		p.log.Error("proxy reload after restore", "err", err)
	}
	writeJSON(w, 200, map[string]any{
		"ok":      true,
		"message": fmt.Sprintf("%d مسیر و %d کلاینت بازیابی شد.", len(doc.Routes), len(doc.Clients)),
	})
}
