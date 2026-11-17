// Package panel serves the operator dashboard, the JSON API and the
// client-facing portal/registration pages.
package panel

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"html"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/farazghri-cloud/best-dns/internal/dnsrv"
	"github.com/farazghri-cloud/best-dns/internal/metrics"
	"github.com/farazghri-cloud/best-dns/internal/proxy"
	"github.com/farazghri-cloud/best-dns/internal/store"
	"github.com/farazghri-cloud/best-dns/internal/webui"
)

const sessionCookie = "bd_sess"

// Panel is the HTTP front end.
type Panel struct {
	store   *store.Store
	stats   *metrics.Stats
	dns     *dnsrv.Server
	proxy   *proxy.Proxy
	log     *slog.Logger
	version string

	mux    *http.ServeMux
	server *http.Server

	attempts *attemptTracker
	started  time.Time
}

// New wires the panel.
func New(st *store.Store, stats *metrics.Stats, dns *dnsrv.Server, px *proxy.Proxy, log *slog.Logger, version string) *Panel {
	p := &Panel{
		store:    st,
		stats:    stats,
		dns:      dns,
		proxy:    px,
		log:      log,
		version:  version,
		mux:      http.NewServeMux(),
		attempts: newAttemptTracker(),
		started:  time.Now(),
	}
	p.routes()
	return p
}

// Handler returns the root handler.
func (p *Panel) Handler() http.Handler { return p.mux }

// ListenAndServe binds the panel.
func (p *Panel) ListenAndServe(addr string) error {
	p.server = &http.Server{
		Addr:              addr,
		Handler:           p.mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}
	p.log.Info("panel listening", "addr", addr)
	return p.server.ListenAndServe()
}

// Close shuts the panel down.
func (p *Panel) Close() error {
	if p.server != nil {
		return p.server.Close()
	}
	return nil
}

func (p *Panel) routes() {
	p.mux.HandleFunc("GET /{$}", p.root)
	p.mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	p.mux.HandleFunc("GET /login", p.loginPage)
	p.mux.HandleFunc("POST /api/login", p.login)
	p.mux.HandleFunc("POST /api/logout", p.logout)

	p.mux.HandleFunc("GET /static/", p.static)
	p.mux.HandleFunc("GET /dash", p.auth(p.dashboard))

	p.mux.HandleFunc("GET /api/state", p.auth(p.apiState))
	p.mux.HandleFunc("GET /api/stats", p.auth(p.apiStats))
	p.mux.HandleFunc("POST /api/routes", p.auth(p.apiRouteCreate))
	p.mux.HandleFunc("PUT /api/routes/{id}", p.auth(p.apiRouteUpdate))
	p.mux.HandleFunc("DELETE /api/routes/{id}", p.auth(p.apiRouteDelete))
	p.mux.HandleFunc("POST /api/clients", p.auth(p.apiClientCreate))
	p.mux.HandleFunc("PUT /api/clients/{id}", p.auth(p.apiClientUpdate))
	p.mux.HandleFunc("DELETE /api/clients/{id}", p.auth(p.apiClientDelete))
	p.mux.HandleFunc("POST /api/clients/{id}/rotate", p.auth(p.apiClientRotate))
	p.mux.HandleFunc("POST /api/clients/{id}/reset", p.auth(p.apiClientReset))
	p.mux.HandleFunc("POST /api/settings", p.auth(p.apiSettings))
	p.mux.HandleFunc("POST /api/password", p.auth(p.apiPassword))
	p.mux.HandleFunc("POST /api/cache/flush", p.auth(p.apiFlush))
	p.mux.HandleFunc("GET /api/backup", p.auth(p.apiBackup))
	p.mux.HandleFunc("POST /api/restore", p.auth(p.apiRestore))

	p.mux.HandleFunc("GET /ip/{token}", p.register)
	p.mux.HandleFunc("POST /ip/{token}", p.register)
	p.mux.HandleFunc("GET /p/{token}", p.portal)
}

/* ── auth ──────────────────────────────────────────────── */

func (p *Panel) sign(exp string) string {
	mac := hmac.New(sha256.New, p.store.SessionKey())
	mac.Write([]byte("v1|" + exp))
	return hex.EncodeToString(mac.Sum(nil))
}

func (p *Panel) newSession(w http.ResponseWriter, r *http.Request) {
	exp := strconv.FormatInt(time.Now().Add(12*time.Hour).Unix(), 10)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    exp + "." + p.sign(exp),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   isHTTPS(r),
		MaxAge:   12 * 3600,
	})
}

func (p *Panel) authed(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return false
	}
	parts := strings.SplitN(c.Value, ".", 2)
	if len(parts) != 2 {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(p.sign(parts[0])), []byte(parts[1])) != 1 {
		return false
	}
	sec, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || time.Now().After(time.Unix(sec, 0)) {
		return false
	}
	return true
}

func (p *Panel) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !p.authed(r) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "برای ادامه وارد شوید"})
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if r.Header.Get("X-Requested-With") != "bestdns" {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "درخواست نامعتبر"})
				return
			}
		}
		h(w, r)
	}
}

/* ── pages ─────────────────────────────────────────────── */

func (p *Panel) title() string {
	t := p.store.Settings().PanelTitle
	if strings.TrimSpace(t) == "" {
		return "BESTPRIME DNS"
	}
	return t
}

func (p *Panel) root(w http.ResponseWriter, r *http.Request) {
	if p.authed(r) {
		http.Redirect(w, r, "/dash", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (p *Panel) loginPage(w http.ResponseWriter, r *http.Request) {
	if p.authed(r) {
		http.Redirect(w, r, "/dash", http.StatusSeeOther)
		return
	}
	p.render(w, "login.html")
}

func (p *Panel) dashboard(w http.ResponseWriter, r *http.Request) {
	p.render(w, "index.html")
}

func (p *Panel) render(w http.ResponseWriter, name string) {
	raw, err := webui.Read(name)
	if err != nil {
		http.Error(w, "asset missing", http.StatusInternalServerError)
		return
	}
	page := strings.ReplaceAll(string(raw), "__TITLE__", html.EscapeString(p.title()))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "same-origin")
	_, _ = w.Write([]byte(page))
}

func (p *Panel) static(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/static/")
	if name == "" || strings.Contains(name, "..") {
		http.NotFound(w, r)
		return
	}
	raw, err := webui.Read(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	switch {
	case strings.HasSuffix(name, ".css"):
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case strings.HasSuffix(name, ".js"):
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	case strings.HasSuffix(name, ".svg"):
		w.Header().Set("Content-Type", "image/svg+xml")
	}
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(raw)
}

/* ── login ─────────────────────────────────────────────── */

func (p *Panel) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !p.attempts.allow(ip) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "تلاش‌های ناموفق زیاد بود؛ چند دقیقه بعد امتحان کن"})
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "درخواست نامعتبر"})
		return
	}
	if !p.store.VerifyPassword(body.Password) {
		p.attempts.fail(ip)
		p.log.Warn("failed panel login", "ip", ip)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "رمز عبور اشتباه است"})
		return
	}
	p.attempts.reset(ip)
	p.newSession(w, r)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "temporary": p.store.TemporaryPassword()})
}

func (p *Panel) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: isHTTPS(r),
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

/* ── helpers ───────────────────────────────────────────── */

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

func decodeJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 2<<20))
	return dec.Decode(v)
}

func clientIP(r *http.Request) string {
	if v := r.Header.Get("CF-Connecting-IP"); v != "" {
		return strings.TrimSpace(v)
	}
	if v := r.Header.Get("X-Real-IP"); v != "" {
		return strings.TrimSpace(v)
	}
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		if i := strings.IndexByte(v, ','); i > 0 {
			return strings.TrimSpace(v[:i])
		}
		return strings.TrimSpace(v)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// attemptTracker throttles password guessing.
type attemptTracker struct {
	mu   sync.Mutex
	data map[string]*attempt
}

type attempt struct {
	count int
	until time.Time
}

func newAttemptTracker() *attemptTracker {
	return &attemptTracker{data: make(map[string]*attempt)}
}

func (t *attemptTracker) allow(ip string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	a, ok := t.data[ip]
	if !ok {
		return true
	}
	if time.Now().After(a.until) {
		delete(t.data, ip)
		return true
	}
	return a.count < 6
}

func (t *attemptTracker) fail(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	a, ok := t.data[ip]
	if !ok || time.Now().After(a.until) {
		a = &attempt{}
		t.data[ip] = a
	}
	a.count++
	a.until = time.Now().Add(10 * time.Minute)
}

func (t *attemptTracker) reset(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.data, ip)
}

// WriteInitialPassword persists the first-run password next to the state file
// and returns its path (best effort; the panel still works if it fails).
func WriteInitialPassword(statePath, pw string) string {
	path := strings.TrimSuffix(statePath, ".json") + "-first-login.txt"
	content := "BESTPRIME DNS — first run credentials\n\npassword: " + pw + "\n\n" +
		"Change it from the panel (Settings → password) and delete this file.\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return ""
	}
	return path
}
