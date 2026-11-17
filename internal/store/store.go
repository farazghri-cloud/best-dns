// Package store holds the daemon's persistent state: settings, the manual
// routes the operator defines, and the client accounts. Everything lives in a
// single JSON document written atomically, so a crash can never leave a
// half-written file behind.
package store

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Route is one operator-defined group of domains. It replaces the upstream
// project's built-in platform presets: nothing is proxied unless it was added
// here by hand.
type Route struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Color     string    `json:"color"`
	Domains   []string  `json:"domains"`
	Public    bool      `json:"public"`  // applies to every allowed client
	Enabled   bool      `json:"enabled"`
	Note      string    `json:"note"`
	CreatedAt time.Time `json:"created_at"`
}

// Client is one subscriber account. Access is bound to source IPs that the
// client itself refreshes through its registration token.
type Client struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Token      string     `json:"token"`
	IPs        []string   `json:"ips"`
	RouteIDs   []string   `json:"route_ids"`
	Enabled    bool       `json:"enabled"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	QuotaBytes uint64     `json:"quota_bytes"` // 0 = unlimited
	UsedBytes  uint64     `json:"used_bytes"`
	Queries    uint64     `json:"queries"`
	Note       string     `json:"note"`
	CreatedAt  time.Time  `json:"created_at"`
	LastSeen   time.Time  `json:"last_seen"`
}

// Settings are runtime knobs editable from the panel.
type Settings struct {
	PanelTitle   string   `json:"panel_title"`
	ProxyIP      string   `json:"proxy_ip"`      // answer for routed names; empty = auto-detect
	ProxyPorts   []int    `json:"proxy_ports"`   // SNI proxy listeners
	Upstreams    []string `json:"upstreams"`     // "ip:port"
	CacheTTL     int      `json:"cache_ttl"`     // seconds, plain lookups
	RoutedTTL    int      `json:"routed_ttl"`    // seconds, answers pointing at ProxyIP
	AllowAll     bool     `json:"allow_all"`     // serve unregistered sources
	RateLimit    int      `json:"rate_limit"`    // queries/second per source, 0 = off
	MaxConns     int      `json:"max_conns"`     // concurrent proxy relays
	DoHPort      string   `json:"doh_port"`      // optional DNS-over-HTTPS listener
	ProxyTimeout int      `json:"proxy_timeout"` // seconds for dial + sniff
	Fragment     bool     `json:"fragment"`      // split ClientHello towards origin
	AnswerIPv6   bool     `json:"answer_ipv6"`   // reply AAAA for routed names
	BlockedIPv6  bool     `json:"blocked_ipv6"`  // answer AAAA with :: (unreachable)
}

// DefaultSettings returns a sane first-run configuration.
func DefaultSettings() Settings {
	return Settings{
		PanelTitle:   "BESTPRIME DNS",
		ProxyPorts:   []int{443},
		Upstreams:    []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"},
		CacheTTL:     300,
		RoutedTTL:    60,
		AllowAll:     false,
		RateLimit:    60,
		MaxConns:     2048,
		ProxyTimeout: 10,
		Fragment:     false,
	}
}

// State is the on-disk document.
type State struct {
	Version    int       `json:"version"`
	Settings   Settings  `json:"settings"`
	Routes     []Route   `json:"routes"`
	Clients    []Client  `json:"clients"`
	AdminSalt  string    `json:"admin_salt"`
	AdminHash  string    `json:"admin_hash"`
	SessionKey string    `json:"session_key"`
	PasswordIs bool      `json:"password_is_temporary"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Store serialises access to the state document.
type Store struct {
	mu    sync.RWMutex
	path  string
	state State

	dirty bool
	matcher *Matcher
}

// ErrNotFound is returned by lookups that miss.
var ErrNotFound = errors.New("not found")

// Open loads (or initialises) the state file at path.
func Open(path string) (*Store, error) {
	s := &Store{path: path}
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(raw, &s.state); err != nil {
			return nil, fmt.Errorf("state file %s is corrupt: %w", path, err)
		}
	case errors.Is(err, os.ErrNotExist):
		s.state = State{Version: 1, Settings: DefaultSettings()}
		s.dirty = true
	default:
		return nil, err
	}
	s.migrate()
	s.rebuild()
	if s.dirty {
		if err := s.saveLocked(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) migrate() {
	if s.state.Version == 0 {
		s.state.Version = 1
	}
	if len(s.state.Settings.Upstreams) == 0 {
		s.state.Settings.Upstreams = DefaultSettings().Upstreams
	}
	if len(s.state.Settings.ProxyPorts) == 0 {
		s.state.Settings.ProxyPorts = []int{443}
	}
	if s.state.Settings.RoutedTTL == 0 {
		s.state.Settings.RoutedTTL = 60
	}
	if s.state.Settings.CacheTTL == 0 {
		s.state.Settings.CacheTTL = 300
	}
	if s.state.Settings.MaxConns == 0 {
		s.state.Settings.MaxConns = 2048
	}
	if s.state.Settings.ProxyTimeout == 0 {
		s.state.Settings.ProxyTimeout = 10
	}
	if s.state.Settings.PanelTitle == "" {
		s.state.Settings.PanelTitle = "BESTPRIME DNS"
	}
	if s.state.SessionKey == "" {
		s.state.SessionKey = randomHex(32)
		s.dirty = true
	}
}

// Path returns the state file location.
func (s *Store) Path() string { return s.path }

func (s *Store) saveLocked() error {
	s.state.UpdatedAt = time.Now()
	buf, err := json.MarshalIndent(&s.state, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		// best effort, windows does not support it
		_ = err
	}
	if _, err := tmp.Write(buf); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, s.path); err != nil {
		return err
	}
	s.dirty = false
	return nil
}

// Save flushes pending changes.
func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

// MarkDirty asks the periodic flusher to save soon.
func (s *Store) MarkDirty() {
	s.mu.Lock()
	s.dirty = true
	s.mu.Unlock()
}

// Dirty reports whether unsaved changes exist.
func (s *Store) Dirty() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dirty
}

// Snapshot returns a deep copy of the state.
func (s *Store) Snapshot() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cloneLocked()
}

func (s *Store) cloneLocked() State {
	buf, _ := json.Marshal(&s.state)
	var out State
	_ = json.Unmarshal(buf, &out)
	return out
}

// Settings returns a copy of the current settings.
func (s *Store) Settings() Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := s.state.Settings
	st.ProxyPorts = append([]int(nil), st.ProxyPorts...)
	st.Upstreams = append([]string(nil), st.Upstreams...)
	return st
}

// UpdateSettings applies fn to a copy of settings and stores the result.
func (s *Store) UpdateSettings(fn func(*Settings) error) (Settings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.state.Settings
	if err := fn(&st); err != nil {
		return st, err
	}
	s.state.Settings = st
	if err := s.saveLocked(); err != nil {
		return st, err
	}
	return st, nil
}

// ---- routes ----

// Routes returns all routes sorted by creation time.
func (s *Store) Routes() []Route {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Route, 0, len(s.state.Routes))
	out = append(out, s.state.Routes...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// Route returns one route by id.
func (s *Store) Route(id string) (Route, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.state.Routes {
		if r.ID == id {
			return r, nil
		}
	}
	return Route{}, ErrNotFound
}

// CreateRoute adds a route.
func (s *Store) CreateRoute(r Route) (Route, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r.Name = strings.TrimSpace(r.Name)
	if r.Name == "" {
		return r, errors.New("نام مسیر نمیتواند خالی باشد")
	}
	if r.ID == "" {
		r.ID = randomHex(6)
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now()
	}
	r.Domains = NormalizeDomains(r.Domains)
	if r.Color == "" {
		r.Color = pickColor(len(s.state.Routes))
	}
	s.state.Routes = append(s.state.Routes, r)
	if err := s.saveLocked(); err != nil {
		return r, err
	}
	s.rebuildLocked()
	return r, nil
}

// UpdateRoute replaces a route.
func (s *Store) UpdateRoute(id string, upd Route) (Route, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.Routes {
		if s.state.Routes[i].ID != id {
			continue
		}
		upd.ID = id
		upd.CreatedAt = s.state.Routes[i].CreatedAt
		upd.Name = strings.TrimSpace(upd.Name)
		if upd.Name == "" {
			return Route{}, errors.New("نام مسیر نمی‌تواند خالی باشد")
		}
		upd.Domains = NormalizeDomains(upd.Domains)
		if upd.Color == "" {
			upd.Color = s.state.Routes[i].Color
		}
		s.state.Routes[i] = upd
		if err := s.saveLocked(); err != nil {
			return upd, err
		}
		s.rebuildLocked()
		return upd, nil
	}
	return Route{}, ErrNotFound
}

// DeleteRoute removes a route and detaches it from clients.
func (s *Store) DeleteRoute(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.state.Routes[:0]
	found := false
	for _, r := range s.state.Routes {
		if r.ID == id {
			found = true
			continue
		}
		out = append(out, r)
	}
	if !found {
		return ErrNotFound
	}
	s.state.Routes = out
	for i := range s.state.Clients {
		s.state.Clients[i].RouteIDs = removeString(s.state.Clients[i].RouteIDs, id)
	}
	if err := s.saveLocked(); err != nil {
		return err
	}
	s.rebuildLocked()
	return nil
}

// ---- clients ----

// Clients returns all clients.
func (s *Store) Clients() []Client {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Client, 0, len(s.state.Clients))
	out = append(out, s.state.Clients...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// Client returns one client by id.
func (s *Store) Client(id string) (Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, c := range s.state.Clients {
		if c.ID == id {
			return c, nil
		}
	}
	return Client{}, ErrNotFound
}

// ClientByToken looks a client up by its registration token.
func (s *Store) ClientByToken(token string) (Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, c := range s.state.Clients {
		if subtle.ConstantTimeCompare([]byte(c.Token), []byte(token)) == 1 {
			return c, nil
		}
	}
	return Client{}, ErrNotFound
}

// ClientByIP finds the active client owning an address.
func (s *Store) ClientByIP(ip string) (Client, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, c := range s.state.Clients {
		if !c.Active(time.Now()) {
			continue
		}
		for _, a := range c.IPs {
			if a == ip {
				return c, true
			}
		}
	}
	return Client{}, false
}

// CreateClient adds a client.
func (s *Store) CreateClient(c Client) (Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c.Name = strings.TrimSpace(c.Name)
	if c.Name == "" {
		return c, errors.New("نام کلاینت نمی‌تواند خالی باشد")
	}
	if c.ID == "" {
		c.ID = randomHex(6)
	}
	if c.Token == "" {
		c.Token = randomToken()
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now()
	}
	if c.IPs == nil {
		c.IPs = []string{}
	}
	if c.RouteIDs == nil {
		c.RouteIDs = []string{}
	}
	s.state.Clients = append(s.state.Clients, c)
	if err := s.saveLocked(); err != nil {
		return c, err
	}
	return c, nil
}

// UpdateClient replaces the editable fields of a client.
func (s *Store) UpdateClient(id string, upd Client) (Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.Clients {
		c := &s.state.Clients[i]
		if c.ID != id {
			continue
		}
		c.Name = strings.TrimSpace(upd.Name)
		if c.Name == "" {
			return *c, errors.New("نام کلاینت نمی‌تواند خالی باشد")
		}
		c.RouteIDs = uniqueStrings(upd.RouteIDs)
		c.Enabled = upd.Enabled
		c.ExpiresAt = upd.ExpiresAt
		c.QuotaBytes = upd.QuotaBytes
		c.Note = upd.Note
		if ups := uniqueStrings(upd.IPs); len(ups) > 0 || len(upd.IPs) == 0 {
			c.IPs = ups
		}
		if upd.Token != "" && upd.Token != c.Token {
			c.Token = upd.Token
		}
		if err := s.saveLocked(); err != nil {
			return *c, err
		}
		return *c, nil
	}
	return Client{}, ErrNotFound
}

// DeleteClient removes a client.
func (s *Store) DeleteClient(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.state.Clients[:0]
	found := false
	for _, c := range s.state.Clients {
		if c.ID == id {
			found = true
			continue
		}
		out = append(out, c)
	}
	if !found {
		return ErrNotFound
	}
	s.state.Clients = out
	return s.saveLocked()
}

// BindIP replaces the client's address list with a single fresh address and
// records the sighting. This is the 1-click /ip/{token} flow.
func (s *Store) BindIP(id, ip string) (Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.Clients {
		c := &s.state.Clients[i]
		if c.ID != id {
			continue
		}
		c.IPs = []string{ip}
		c.LastSeen = time.Now()
		if err := s.saveLocked(); err != nil {
			return *c, err
		}
		return *c, nil
	}
	return Client{}, ErrNotFound
}

// RotateToken issues a new registration token.
func (s *Store) RotateToken(id string) (Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.Clients {
		c := &s.state.Clients[i]
		if c.ID != id {
			continue
		}
		c.Token = randomToken()
		if err := s.saveLocked(); err != nil {
			return *c, err
		}
		return *c, nil
	}
	return Client{}, ErrNotFound
}

// ResetUsage zeroes a client's counters.
func (s *Store) ResetUsage(id string) (Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.Clients {
		c := &s.state.Clients[i]
		if c.ID != id {
			continue
		}
		c.UsedBytes = 0
		c.Queries = 0
		if err := s.saveLocked(); err != nil {
			return *c, err
		}
		return *c, nil
	}
	return Client{}, ErrNotFound
}

// AddUsage accumulates traffic and query counters for a batch of clients.
func (s *Store) AddUsage(perClient map[string]Counter) {
	if len(perClient) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.Clients {
		c := &s.state.Clients[i]
		d, ok := perClient[c.ID]
		if !ok {
			continue
		}
		c.UsedBytes += d.Bytes
		c.Queries += d.Queries
		if d.LastSeen.After(c.LastSeen) {
			c.LastSeen = d.LastSeen
		}
	}
	s.dirty = true
}

// Counter is a usage delta.
type Counter struct {
	Bytes    uint64
	Queries  uint64
	LastSeen time.Time
}

// Match reports whether name is routed, and by which routes.
func (s *Store) Match(name string) []string {
	s.mu.RLock()
	m := s.matcher
	s.mu.RUnlock()
	if m == nil {
		return nil
	}
	return m.Match(name)
}

// Rebuild recompiles the matcher (call after bulk edits).
func (s *Store) Rebuild() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rebuildLocked()
}

func (s *Store) rebuild() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rebuildLocked()
}

func (s *Store) rebuildLocked() {
	m := NewMatcher()
	for _, r := range s.state.Routes {
		if !r.Enabled {
			continue
		}
		for _, d := range r.Domains {
			m.Add(d, r.ID)
		}
	}
	s.matcher = m
}

// ---- admin credentials ----

// SetPassword stores a fresh PBKDF2 verifier.
func (s *Store) SetPassword(pw string, temporary bool) error {
	if len(pw) < 6 {
		return errors.New("رمز عبور باید حداقل ۶ کاراکتر باشد")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	salt := randomHex(16)
	s.state.AdminSalt = salt
	s.state.AdminHash = HashPassword(pw, salt)
	s.state.PasswordIs = temporary
	return s.saveLocked()
}

// VerifyPassword checks a password in constant time.
func (s *Store) VerifyPassword(pw string) bool {
	s.mu.RLock()
	salt, hash := s.state.AdminSalt, s.state.AdminHash
	s.mu.RUnlock()
	if salt == "" || hash == "" {
		return false
	}
	got := HashPassword(pw, salt)
	return subtle.ConstantTimeCompare([]byte(got), []byte(hash)) == 1
}

// HasPassword reports whether an admin password was ever set.
func (s *Store) HasPassword() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.AdminHash != ""
}

// SessionKey returns the HMAC key used to sign panel cookies.
func (s *Store) SessionKey() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return []byte(s.state.SessionKey)
}

// TemporaryPassword reports whether the password is still the generated one.
func (s *Store) TemporaryPassword() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.PasswordIs
}

// ReplaceState swaps in an imported document (backup restore).
func (s *Store) ReplaceState(st State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = st
	s.migrate()
	if err := s.saveLocked(); err != nil {
		return err
	}
	s.rebuildLocked()
	return nil
}

// ---- helpers ----

// HashPassword derives a PBKDF2-HMAC-SHA256 verifier (120k iterations).
func HashPassword(pw, saltHex string) string {
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return ""
	}
	dk := pbkdf2SHA256([]byte(pw), salt, 120000, 32)
	return hex.EncodeToString(dk)
}

func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	blocks := (keyLen + hashLen - 1) / hashLen
	out := make([]byte, 0, blocks*hashLen)
	u := make([]byte, hashLen)
	t := make([]byte, hashLen)
	var idx [4]byte
	for block := 1; block <= blocks; block++ {
		prf.Reset()
		prf.Write(salt)
		idx[0] = byte(block >> 24)
		idx[1] = byte(block >> 16)
		idx[2] = byte(block >> 8)
		idx[3] = byte(block)
		prf.Write(idx[:])
		u = prf.Sum(u[:0])
		copy(t, u)
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for i := range t {
				t[i] ^= u[i]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

const tokenAlphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// randomToken returns a 22-character URL-safe registration token.
func randomToken() string {
	b := make([]byte, 22)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	for i := range b {
		b[i] = tokenAlphabet[int(b[i])%len(tokenAlphabet)]
	}
	return string(b)
}

// RandomToken is the exported generator (used for the initial password).
func RandomToken() string { return randomToken() }

// RandomHex is the exported hex generator.
func RandomHex(n int) string { return randomHex(n) }

// GeneratePassword returns a human-friendly 12-character password.
func GeneratePassword() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	for i := range b {
		b[i] = tokenAlphabet[int(b[i])%len(tokenAlphabet)]
	}
	return string(b)
}

var palette = []string{"#22d3ee", "#a78bfa", "#f472b6", "#34d399", "#fbbf24", "#fb7185", "#60a5fa", "#f97316"}

func pickColor(i int) string { return palette[i%len(palette)] }

func removeString(in []string, v string) []string {
	out := in[:0]
	for _, s := range in {
		if s != v {
			out = append(out, s)
		}
	}
	return out
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// Active reports whether the account may be served right now.
func (c Client) Active(now time.Time) bool {
	if !c.Enabled {
		return false
	}
	if c.ExpiresAt != nil && now.After(*c.ExpiresAt) {
		return false
	}
	if c.QuotaBytes > 0 && c.UsedBytes >= c.QuotaBytes {
		return false
	}
	return true
}

// Remaining returns the remaining quota in bytes (0 = unlimited).
func (c Client) Remaining() uint64 {
	if c.QuotaBytes == 0 {
		return 0
	}
	if c.UsedBytes >= c.QuotaBytes {
		return 0
	}
	return c.QuotaBytes - c.UsedBytes
}

// Base64Std is a tiny helper used by the panel for backup export names.
func Base64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
