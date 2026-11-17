// Package proxy is the layer-4 SNI relay. It reads the TLS ClientHello (or the
// HTTP Host header) of an incoming connection, decides — from the operator's
// own routes and the caller's account — whether the name may be relayed, then
// connects to the real origin and copies bytes in both directions. The TLS
// session stays end to end: no certificate is ever presented or terminated.
package proxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/farazghri-cloud/best-dns/internal/metrics"
	"github.com/farazghri-cloud/best-dns/internal/store"
)

// Resolver turns a host name into an origin address.
type Resolver interface {
	ResolveIPv4(host string) (string, error)
}

// Proxy owns the relay listeners.
type Proxy struct {
	store    *store.Store
	stats    *metrics.Stats
	log      *slog.Logger
	resolver Resolver

	sem       chan struct{}
	listeners map[int]net.Listener
	mu        sync.Mutex
	done      chan struct{}
	conns     atomic.Int64
	active    atomic.Int64
}

// New builds a proxy. maxConns caps concurrent relays.
func New(st *store.Store, stats *metrics.Stats, log *slog.Logger, resolver Resolver, maxConns int) *Proxy {
	if maxConns <= 0 {
		maxConns = 2048
	}
	return &Proxy{
		store:     st,
		stats:     stats,
		log:       log,
		resolver:  resolver,
		sem:       make(chan struct{}, maxConns),
		listeners: make(map[int]net.Listener),
		done:      make(chan struct{}),
	}
}

// Listen starts a listener per configured port.
func (p *Proxy) Listen(ports []int) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, port := range ports {
		if port <= 0 || port > 65535 {
			continue
		}
		if _, ok := p.listeners[port]; ok {
			continue
		}
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			return fmt.Errorf("proxy port %d: %w", port, err)
		}
		p.listeners[port] = ln
		go p.acceptLoop(ln, port)
		p.log.Info("sni relay up", "port", port)
	}
	return nil
}

// Close stops every listener.
func (p *Proxy) Close() {
	close(p.done)
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, ln := range p.listeners {
		_ = ln.Close()
	}
	p.listeners = nil
}

// Reload swaps the listener set without stopping the accept loops of ports
// that stay in place.
func (p *Proxy) Reload(ports []int) error {
	want := make(map[int]bool, len(ports))
	for _, port := range ports {
		if port > 0 && port < 65536 {
			want[port] = true
		}
	}
	p.mu.Lock()
	for port, ln := range p.listeners {
		if !want[port] {
			_ = ln.Close()
			delete(p.listeners, port)
		}
	}
	var missing []int
	for port := range want {
		if _, ok := p.listeners[port]; !ok {
			missing = append(missing, port)
		}
	}
	p.mu.Unlock()
	return p.Listen(missing)
}

// Active returns the number of in-flight relays.
func (p *Proxy) Active() int { return int(p.active.Load()) }

// Ports returns the ports currently listened on.
func (p *Proxy) Ports() []int {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]int, 0, len(p.listeners))
	for port := range p.listeners {
		out = append(out, port)
	}
	return out
}

func (p *Proxy) acceptLoop(ln net.Listener, port int) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-p.done:
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			// transient fd exhaustion: back off instead of spinning
			time.Sleep(50 * time.Millisecond)
			continue
		}
		select {
		case p.sem <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		p.conns.Add(1)
		go func() {
			defer func() {
				<-p.sem
				p.conns.Add(-1)
			}()
			p.handle(conn, port)
		}()
	}
}

func (p *Proxy) settings() store.Settings { return p.store.Settings() }

func (p *Proxy) handle(conn net.Conn, port int) {
	settings := p.settings()
	timeout := time.Duration(settings.ProxyTimeout) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	srcIP := hostOnly(conn.RemoteAddr().String())
	client, known := p.store.ClientByIP(srcIP)
	if known && !client.Active(time.Now()) {
		return
	}
	if !known && !settings.AllowAll && !isLoopback(srcIP) {
		return
	}
	clientID := ""
	if known {
		clientID = client.ID
	}

	pre, host, isTLS, err := sniff(conn)
	if err != nil || host == "" {
		p.stats.ProxyConn(false, uint64(len(pre)), clientID)
		return
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if !p.allowed(host, client, known) {
		p.stats.ProxyConn(false, uint64(len(pre)), clientID)
		return
	}

	// The listener port is ours; the origin always speaks 443 (TLS) or 80
	// (plain HTTP). That is what makes 443, 8443 or any other inbound port
	// behave identically for the client.
	targetPort := 443
	if !isTLS {
		targetPort = 80
	}
	ip, err := p.resolver.ResolveIPv4(host)
	if err != nil || ip == "" {
		p.stats.ProxyConn(false, uint64(len(pre)), clientID)
		return
	}
	if self := p.selfIP(); self != "" && ip == self {
		p.stats.ProxyConn(false, uint64(len(pre)), clientID)
		return
	}

	upstream, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(targetPort)), timeout)
	if err != nil {
		p.stats.ProxyConn(false, uint64(len(pre)), clientID)
		return
	}
	defer upstream.Close()
	_ = conn.SetDeadline(time.Time{})
	_ = upstream.SetDeadline(time.Time{})

	// Replay the sniffed bytes (optionally split to break naive DPI).
	if settings.Fragment && isTLS && len(pre) > 8 {
		if err := writeFragmented(upstream, pre); err != nil {
			p.stats.ProxyConn(false, uint64(len(pre)), clientID)
			return
		}
	} else if len(pre) > 0 {
		if _, err := upstream.Write(pre); err != nil {
			p.stats.ProxyConn(false, uint64(len(pre)), clientID)
			return
		}
	}

	p.active.Add(1)
	var up, down atomic.Uint64
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, _ := io.Copy(upstream, conn)
		up.Store(uint64(n))
		if tc, ok := upstream.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		n, _ := io.Copy(conn, upstream)
		down.Store(uint64(n))
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	wg.Wait()
	p.active.Add(-1)
	p.stats.ProxyConn(true, up.Load()+down.Load()+uint64(len(pre)), clientID)
}

func (p *Proxy) allowed(host string, client store.Client, known bool) bool {
	if host == "" {
		return false
	}
	groups := make(map[string]bool)
	for _, r := range p.store.Routes() {
		if r.Enabled && r.Public {
			groups[r.ID] = true
		}
	}
	if known && client.Active(time.Now()) {
		for _, id := range client.RouteIDs {
			groups[id] = true
		}
	}
	if len(groups) == 0 {
		return false
	}
	for _, id := range p.store.Match(host) {
		if groups[id] {
			return true
		}
	}
	return false
}

func (p *Proxy) selfIP() string {
	ip := p.settings().ProxyIP
	if ip == "" {
		return ""
	}
	return strings.TrimSpace(ip)
}

// sniff reads the first bytes of a connection and extracts the requested host
// name. The returned slice must be replayed to the origin.
func sniff(conn net.Conn) (pre []byte, host string, isTLS bool, err error) {
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 2048)
	deadline := time.Now().Add(5 * time.Second)
	for len(buf) < 16384 {
		n, rerr := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if h, tls, ok := parseHost(buf); ok {
				return buf, h, tls, nil
			}
			if isHTTPPrefix(buf) && bytes.Contains(buf, []byte("\r\n\r\n")) {
				return buf, "", false, errors.New("http: no host header")
			}
		}
		if rerr != nil {
			return buf, "", false, rerr
		}
		if time.Now().After(deadline) {
			break
		}
	}
	return buf, "", false, errors.New("sniff: no host name")
}

func isHTTPPrefix(b []byte) bool {
	if len(b) < 3 {
		return false
	}
	for _, m := range []string{"GET", "POST", "HEAD", "PUT", "CONN", "OPTI", "DELE", "PATC", "TRAC"} {
		if bytes.HasPrefix(b, []byte(m)) {
			return true
		}
	}
	return false
}

// parseHost tries TLS ClientHello SNI first, then an HTTP Host header.
func parseHost(b []byte) (host string, isTLS bool, ok bool) {
	if len(b) >= 5 && b[0] == 0x16 && b[1] == 0x03 {
		recLen := int(binary.BigEndian.Uint16(b[3:5]))
		if recLen == 0 || len(b) < 5+recLen {
			return "", true, false
		}
		if h, ok := parseClientHello(b[5 : 5+recLen]); ok {
			return h, true, true
		}
		// handshake may be split over records: try growing the window
		if h, ok := parseClientHello(b[5:]); ok {
			return h, true, true
		}
		return "", true, false
	}
	if isHTTPPrefix(b) {
		if h, ok := parseHTTPHost(b); ok {
			return h, false, true
		}
	}
	return "", false, false
}

func parseClientHello(b []byte) (string, bool) {
	if len(b) < 4 || b[0] != 0x01 {
		return "", false
	}
	hsLen := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if hsLen <= 0 || len(b) < 4+hsLen {
		return "", false
	}
	b = b[4 : 4+hsLen]
	// version(2) random(32)
	if len(b) < 34 {
		return "", false
	}
	p := 34
	if p >= len(b) {
		return "", false
	}
	sidLen := int(b[p])
	p += 1 + sidLen
	if p+2 > len(b) {
		return "", false
	}
	csLen := int(binary.BigEndian.Uint16(b[p : p+2]))
	p += 2 + csLen
	if p >= len(b) {
		return "", false
	}
	compLen := int(b[p])
	p += 1 + compLen
	if p+2 > len(b) {
		return "", false
	}
	extLen := int(binary.BigEndian.Uint16(b[p : p+2]))
	p += 2
	end := p + extLen
	if end > len(b) {
		end = len(b)
	}
	for p+4 <= end {
		etype := binary.BigEndian.Uint16(b[p : p+2])
		elen := int(binary.BigEndian.Uint16(b[p+2 : p+4]))
		p += 4
		if p+elen > end {
			return "", false
		}
		if etype == 0 { // server_name
			data := b[p : p+elen]
			if len(data) < 2 {
				return "", false
			}
			listLen := int(binary.BigEndian.Uint16(data[0:2]))
			if listLen+2 > len(data) {
				return "", false
			}
			q := 2
			for q+3 <= 2+listLen {
				ntype := data[q]
				nlen := int(binary.BigEndian.Uint16(data[q+1 : q+3]))
				q += 3
				if q+nlen > len(data) {
					return "", false
				}
				if ntype == 0 && nlen > 0 {
					return string(data[q : q+nlen]), true
				}
				q += nlen
			}
		}
		p += elen
	}
	return "", false
}

func parseHTTPHost(b []byte) (string, bool) {
	idx := bytes.Index(b, []byte("\r\n\r\n"))
	if idx < 0 {
		idx = len(b)
	}
	lines := bytes.Split(b[:idx], []byte("\r\n"))
	for _, line := range lines[1:] {
		low := bytes.ToLower(line)
		if bytes.HasPrefix(low, []byte("host:")) {
			h := strings.TrimSpace(string(line[5:]))
			if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h, "]") {
				if _, err := strconv.Atoi(h[i+1:]); err == nil {
					h = h[:i]
				}
			}
			return h, h != ""
		}
	}
	return "", false
}

func writeFragmented(w io.Writer, data []byte) error {
	// Three chunks with a tiny gap: DPI engines that match a signature across
	// the first TCP segment stop seeing it, while the origin reassembles the
	// stream untouched.
	chunks := []int{1, len(data) / 3, len(data) / 3, len(data)}
	prev := 0
	for i := 1; i < len(chunks); i++ {
		end := chunks[i]
		if end > len(data) {
			end = len(data)
		}
		if end <= prev {
			continue
		}
		if _, err := w.Write(data[prev:end]); err != nil {
			return err
		}
		prev = end
		time.Sleep(3 * time.Millisecond)
	}
	if prev < len(data) {
		_, err := w.Write(data[prev:])
		return err
	}
	return nil
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

func isLoopback(ip string) bool {
	p := net.ParseIP(ip)
	return p != nil && p.IsLoopback()
}
