// Package dnsrv is the smart-DNS front end: it decides, per client and per
// name, whether an answer points at this server (so the SNI proxy relays the
// traffic) or whether the real upstream answer is returned untouched.
package dnsrv

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/farazghri-cloud/best-dns/internal/dnswire"
	"github.com/farazghri-cloud/best-dns/internal/metrics"
	"github.com/farazghri-cloud/best-dns/internal/store"
)

// Server answers DNS queries (UDP, TCP and DoH).
type Server struct {
	store *store.Store
	stats *metrics.Stats
	log   *slog.Logger
	cache *cache

	roundRobin uint32
	rate       *rateLimiter
	pubIP      atomic.Value // string

	udp   *net.UDPConn
	tcp   net.Listener
	doh   *http.Server
	mu    sync.Mutex
	done  chan struct{}
}

// New builds a DNS server bound to the given store.
func New(st *store.Store, stats *metrics.Stats, log *slog.Logger) *Server {
	s := &Server{
		store: st,
		stats: stats,
		log:   log,
		cache: newCache(20000, 30*time.Minute),
		rate:  newRateLimiter(),
		done:  make(chan struct{}),
	}
	s.pubIP.Store("")
	return s
}

// SetPublicIP pins the address that routed names resolve to.
func (s *Server) SetPublicIP(ip string) { s.pubIP.Store(strings.TrimSpace(ip)) }

// PublicIP returns the currently advertised proxy address.
func (s *Server) PublicIP() string {
	v, _ := s.pubIP.Load().(string)
	return v
}

// DetectPublicIP asks a couple of well-known echo services for the address
// this host is seen as. Failure is not fatal: the local listener address is
// used as a fallback.
func (s *Server) DetectPublicIP() {
	if s.PublicIP() != "" {
		return
	}
	urls := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
		"https://api64.ipify.org",
	}
	client := &http.Client{Timeout: 4 * time.Second}
	for _, u := range urls {
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "best-dns")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		cand := strings.TrimSpace(string(body))
		if ip := net.ParseIP(cand); ip != nil && ip.To4() != nil && !ip.IsPrivate() {
			s.SetPublicIP(ip.String())
			s.log.Info("public address detected", "ip", ip.String())
			return
		}
	}
	s.log.Warn("could not detect public address; set it in the panel")
}

// Listen starts the UDP and TCP listeners. Port 53 is the default.
func (s *Server) Listen(udpAddr, tcpAddr, dohAddr string) error {
	if udpAddr != "" {
		addr, err := net.ResolveUDPAddr("udp", udpAddr)
		if err != nil {
			return err
		}
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			return fmt.Errorf("udp %s: %w", udpAddr, err)
		}
		_ = conn.SetReadBuffer(4 << 20)
		_ = conn.SetWriteBuffer(4 << 20)
		s.udp = conn
		go s.serveUDP()
		s.log.Info("dns listener up", "proto", "udp", "addr", udpAddr)
	}
	if tcpAddr != "" {
		ln, err := net.Listen("tcp", tcpAddr)
		if err != nil {
			return fmt.Errorf("tcp %s: %w", tcpAddr, err)
		}
		s.tcp = ln
		go s.serveTCP()
		s.log.Info("dns listener up", "proto", "tcp", "addr", tcpAddr)
	}
	if dohAddr != "" {
		go s.serveDoH(dohAddr)
	}
	return nil
}

// Close stops all listeners.
func (s *Server) Close() {
	close(s.done)
	if s.udp != nil {
		s.udp.Close()
	}
	if s.tcp != nil {
		s.tcp.Close()
	}
	if s.doh != nil {
		_ = s.doh.Close()
	}
}

// FlushCache empties the answer cache.
func (s *Server) FlushCache() { s.cache.flush() }

// CacheStats exposes counters for the panel.
func (s *Server) CacheStats() (int, uint64, uint64, uint64) { return s.cache.stats() }

func (s *Server) serveUDP() {
	buf := make([]byte, 4096)
	for {
		n, addr, err := s.udp.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.done:
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go func() {
			reply := s.Handle(pkt, addr.IP.String(), localIP(s.udp.LocalAddr()), false)
			if len(reply) > 0 {
				_, _ = s.udp.WriteToUDP(reply, addr)
			}
		}()
	}
}

func (s *Server) serveTCP() {
	for {
		conn, err := s.tcp.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		go s.handleTCPConn(conn)
	}
}

func (s *Server) handleTCPConn(conn net.Conn) {
	defer conn.Close()
	src := hostOnly(conn.RemoteAddr().String())
	local := localIP(conn.LocalAddr())
	var lenBuf [2]byte
	for {
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(lenBuf[:]))
		if n == 0 || n > 4096 {
			return
		}
		msg := make([]byte, n)
		if _, err := io.ReadFull(conn, msg); err != nil {
			return
		}
		reply := s.Handle(msg, src, local, true)
		if len(reply) == 0 {
			return
		}
		out := make([]byte, 2+len(reply))
		binary.BigEndian.PutUint16(out[:2], uint16(len(reply)))
		copy(out[2:], reply)
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write(out); err != nil {
			return
		}
	}
}

// Handle processes one raw message and returns the reply (nil = drop).
func (s *Server) Handle(raw []byte, srcIP, localAddr string, tcp bool) []byte {
	req, err := dnswire.Parse(raw)
	if err != nil || len(req.Questions) == 0 {
		return nil
	}
	q := req.Questions[0]
	name := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	hasOPT := false
	for _, rr := range req.Additional {
		if rr.Type == dnswire.TypeOPT {
			hasOPT = true
		}
	}

	// Per-source rate limit, applied before any work is done.
	if s.rate.allow(srcIP, s.store.Settings().RateLimit) == false {
		s.stats.Query(srcIP, name, false, false, true)
		return nil
	}

	client, known := s.store.ClientByIP(srcIP)
	if known && !client.Active(time.Now()) {
		s.stats.Query(srcIP, name, false, false, true)
		return refuse(req, hasOPT)
	}
	if !known {
		if !isLocal(srcIP) && !s.store.Settings().AllowAll {
			s.stats.Query(srcIP, name, false, false, true)
			return refuse(req, hasOPT)
		}
	}

	groups := s.effectiveRoutes(client, known)
	routed := false
	if len(groups) > 0 {
		for _, id := range s.store.Match(name) {
			if groups[id] {
				routed = true
				break
			}
		}
	}
	if known {
		s.stats.ClientQuery(client.ID)
	}

	settings := s.store.Settings()
	switch {
	case routed && q.Type == dnswire.TypeA:
		ip := s.answerIPv4(localAddr)
		if ip == nil {
			s.stats.Failed()
			return servfail(req, hasOPT)
		}
		s.stats.Query(srcIP, name, true, false, false)
		return dnswire.BuildReply(req, dnswire.RcodeNoError, []dnswire.Answer{
			dnswire.AAnswer(*ip, uint32(settings.RoutedTTL)),
		}, hasOPT)

	case routed && q.Type == dnswire.TypeAAAA:
		s.stats.Query(srcIP, name, true, false, false)
		if settings.AnswerIPv6 {
			if v6 := s.answerIPv6(); v6 != nil {
				return dnswire.BuildReply(req, dnswire.RcodeNoError, []dnswire.Answer{
					{Type: dnswire.TypeAAAA, TTL: uint32(settings.RoutedTTL), Data: v6},
				}, hasOPT)
			}
		}
		// NODATA: the client falls back to IPv4, which we can relay.
		return dnswire.BuildReply(req, dnswire.RcodeNoError, nil, hasOPT)

	case routed && (q.Type == dnswire.TypeHTTPS || q.Type == dnswire.TypeNS):
		// Never leak origin hints for names we relay.
		s.stats.Query(srcIP, name, true, false, false)
		return dnswire.BuildReply(req, dnswire.RcodeNoError, nil, hasOPT)
	}

	reply, cached, err := s.forward(name, q.Type, raw)
	if err != nil {
		s.stats.Failed()
		s.stats.Query(srcIP, name, routed, false, false)
		return servfail(req, hasOPT)
	}
	s.stats.Query(srcIP, name, routed, cached, false)
	if !tcp && len(reply) > 512 && !hasOPT {
		reply = dnswire.SetTruncated(reply)
	}
	// keep the client's transaction id
	copy(reply[0:2], raw[0:2])
	return reply
}

func (s *Server) effectiveRoutes(client store.Client, known bool) map[string]bool {
	out := make(map[string]bool, len(client.RouteIDs)+4)
	for _, r := range s.store.Routes() {
		if !r.Enabled {
			continue
		}
		if r.Public {
			out[r.ID] = true
		}
	}
	if known && client.Active(time.Now()) {
		for _, id := range client.RouteIDs {
			out[id] = true
		}
	}
	return out
}

// answerIPv4 resolves the address we hand out for routed names, in order of
// preference: explicit setting, detected public IP, the address the query
// arrived on (public only).
func (s *Server) answerIPv4(localAddr string) *[4]byte {
	candidates := []string{s.store.Settings().ProxyIP, s.PublicIP(), localAddr}
	for _, c := range candidates {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		ip := net.ParseIP(c)
		if ip == nil {
			continue
		}
		if v4 := ip.To4(); v4 != nil {
			var out [4]byte
			copy(out[:], v4)
			return &out
		}
	}
	return nil
}

func (s *Server) answerIPv6() []byte {
	candidates := []string{s.store.Settings().ProxyIP, s.PublicIP()}
	for _, c := range candidates {
		if ip := net.ParseIP(c); ip != nil && ip.To4() == nil {
			return ip.To16()
		}
	}
	return nil
}

// forward sends the query upstream (caching the raw response).
func (s *Server) forward(name string, qtype uint16, raw []byte) ([]byte, bool, error) {
	key := fmt.Sprintf("%s|%d", name, qtype)
	if cached, age, ok := s.cache.get(key); ok {
		reply := make([]byte, len(cached))
		copy(reply, cached)
		return dnswire.DecayTTLs(reply, age), true, nil
	}
	reply, err := s.exchange(raw)
	if err != nil {
		return nil, false, err
	}
	ttl := s.store.Settings().CacheTTL
	if m, perr := dnswire.Parse(reply); perr == nil {
		ttl = int(dnswire.MinTTL(m, uint32(ttl)))
	}
	if ttl > 0 {
		s.cache.put(key, reply, time.Duration(ttl)*time.Second)
	}
	return reply, false, nil
}

// ResolveIPv4 looks a name up against the upstreams, bypassing the routing
// rules. The SNI proxy uses it to find the real origin address.
func (s *Server) ResolveIPv4(name string) (string, error) {
	key := "addr|" + strings.ToLower(name)
	if v, _, ok := s.cache.get(key); ok {
		return string(v), nil
	}
	var lastErr error
	var idBytes [2]byte
	_, _ = rand.Read(idBytes[:])
	q, err := dnswire.NewQuery(binary.BigEndian.Uint16(idBytes[:]), name, dnswire.TypeA)
	if err != nil {
		return "", err
	}
	// Follow CNAME chains (up to 6 hops).
	cur := strings.ToLower(name)
	for hop := 0; hop < 6; hop++ {
		if hop > 0 {
			q, err = dnswire.NewQuery(binary.BigEndian.Uint16(idBytes[:]), cur, dnswire.TypeA)
			if err != nil {
				return "", err
			}
		}
		reply, err := s.exchange(q)
		if err != nil {
			lastErr = err
			break
		}
		m, err := dnswire.Parse(reply)
		if err != nil {
			lastErr = err
			break
		}
		ttl := uint32(30)
		next := ""
		for _, rr := range m.Answers {
			if rr.TTL > 0 && rr.TTL < ttl {
				ttl = rr.TTL
			}
			switch rr.Type {
			case dnswire.TypeA:
				ip := rr.IP()
				if ip != "" {
					s.cache.put(key, []byte(ip), time.Duration(ttl)*time.Second)
					if next != "" {
						s.cache.put("addr|"+cur, []byte(ip), time.Duration(ttl)*time.Second)
					}
					return ip, nil
				}
			case dnswire.TypeCNAME:
				if cname, _, err := dnswire.ReadName(reply, rr.DataPos); err == nil && cname != "" {
					next = strings.ToLower(cname)
				}
			}
		}
		if next == "" {
			lastErr = fmt.Errorf("no A record for %s", cur)
			break
		}
		cur = next
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no A record for %s", name)
	}
	return "", lastErr
}

func (s *Server) exchange(query []byte) ([]byte, error) {
	upstreams := s.store.Settings().Upstreams
	if len(upstreams) == 0 {
		return nil, errors.New("no upstream resolver configured")
	}
	// Fresh transaction id towards the upstream.
	var idb [2]byte
	_, _ = rand.Read(idb[:])
	q := make([]byte, len(query))
	copy(q, query)
	binary.BigEndian.PutUint16(q[0:2], binary.BigEndian.Uint16(idb[:]))

	start := int(atomic.AddUint32(&s.roundRobin, 1)) % len(upstreams)
	var lastErr error
	for i := 0; i < len(upstreams); i++ {
		addr := strings.TrimSpace(upstreams[(start+i)%len(upstreams)])
		if addr == "" {
			continue
		}
		if !strings.Contains(addr, ":") {
			addr += ":53"
		}
		reply, err := udpExchange(addr, q, 3*time.Second)
		if err != nil {
			lastErr = err
			continue
		}
		if len(reply) < 12 {
			lastErr = errors.New("short upstream reply")
			continue
		}
		if binary.BigEndian.Uint16(reply[2:4])&0x0200 != 0 { // TC
			if tcpReply, terr := tcpExchange(addr, q, 3*time.Second); terr == nil {
				reply = tcpReply
			}
		}
		return reply, nil
	}
	if lastErr == nil {
		lastErr = errors.New("all upstreams failed")
	}
	return nil, lastErr
}

func udpExchange(addr string, query []byte, timeout time.Duration) ([]byte, error) {
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		if n < 12 {
			continue
		}
		if binary.BigEndian.Uint16(buf[0:2]) != binary.BigEndian.Uint16(query[0:2]) {
			continue // stray/spoofed datagram
		}
		out := make([]byte, n)
		copy(out, buf[:n])
		return out, nil
	}
}

func tcpExchange(addr string, query []byte, timeout time.Duration) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(query)))
	copy(framed[2:], query)
	if _, err := conn.Write(framed); err != nil {
		return nil, err
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n == 0 || n > 65535 {
		return nil, errors.New("bad tcp frame")
	}
	out := make([]byte, n)
	if _, err := io.ReadFull(conn, out); err != nil {
		return nil, err
	}
	return out, nil
}

// serveDoH exposes RFC 8484 DNS-over-HTTPS on its own port.
func (s *Server) serveDoH(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		var raw []byte
		switch r.Method {
		case http.MethodPost:
			body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
			if err != nil {
				http.Error(w, "bad body", http.StatusBadRequest)
				return
			}
			raw = body
		case http.MethodGet:
			q := r.URL.Query().Get("dns")
			if q == "" {
				http.Error(w, "missing dns parameter", http.StatusBadRequest)
				return
			}
			dec, err := decodeBase64URL(q)
			if err != nil {
				http.Error(w, "bad dns parameter", http.StatusBadRequest)
				return
			}
			raw = dec
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		src := clientIPFromRequest(r)
		reply := s.Handle(raw, src, s.PublicIP(), true)
		if len(reply) == 0 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(reply)
	})
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	s.mu.Lock()
	s.doh = srv
	s.mu.Unlock()
	s.log.Info("doh listener up", "addr", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		s.log.Error("doh listener failed", "err", err)
	}
}

func refuse(req *dnswire.Msg, opt bool) []byte {
	return dnswire.BuildReply(req, dnswire.RcodeRefused, nil, opt)
}

func servfail(req *dnswire.Msg, opt bool) []byte {
	return dnswire.BuildReply(req, dnswire.RcodeServFail, nil, opt)
}

func localIP(a net.Addr) string {
	if a == nil {
		return ""
	}
	return hostOnly(a.String())
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

func isLocal(ip string) bool {
	p := net.ParseIP(ip)
	return p != nil && p.IsLoopback()
}

func clientIPFromRequest(r *http.Request) string {
	remote := hostOnly(r.RemoteAddr)
	if ip := net.ParseIP(remote); ip == nil || !(ip.IsLoopback() || ip.IsPrivate()) {
		// only trust forwarding headers from a local reverse proxy
		return remote
	}
	if v := r.Header.Get("CF-Connecting-IP"); v != "" {
		return v
	}
	if v := r.Header.Get("X-Real-IP"); v != "" {
		return v
	}
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		if i := strings.IndexByte(v, ','); i > 0 {
			return strings.TrimSpace(v[:i])
		}
		return strings.TrimSpace(v)
	}
	return hostOnly(r.RemoteAddr)
}

func decodeBase64URL(s string) ([]byte, error) {
	return base64URLDecode(s)
}
