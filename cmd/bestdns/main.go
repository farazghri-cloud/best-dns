// Command bestdns is the single-binary smart DNS + SNI relay daemon.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/farazghri-cloud/best-dns/internal/dnsrv"
	"github.com/farazghri-cloud/best-dns/internal/metrics"
	"github.com/farazghri-cloud/best-dns/internal/panel"
	"github.com/farazghri-cloud/best-dns/internal/proxy"
	"github.com/farazghri-cloud/best-dns/internal/store"
)

// version is injected at build time with -ldflags "-X main.version=…".
var version = "1.0.0"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "-v", "--version":
			fmt.Printf("bestdns %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
			return
		case "passwd":
			runPasswd(os.Args[2:])
			return
		case "server", "run":
			os.Args = append(os.Args[:1], os.Args[2:]...)
		case "help", "-h", "--help":
			usage()
			return
		}
	}
	runServer(os.Args[1:])
}

func usage() {
	fmt.Print(`BESTPRIME DNS — smart DNS + SNI relay

Usage:
  bestdns server [flags]     run the daemon (default)
  bestdns passwd [flags]     set a new panel password
  bestdns version            print the version

Flags (server):
  -data string    state file path (default /var/lib/bestdns/state.json)
  -dns string     DNS listen address (default :53 for udp+tcp)
  -panel string   panel listen address (default :8080)
  -public-ip      override the advertised proxy address
  -allow-all      serve unregistered clients (also editable in the panel)
  -debug          verbose logging
`)
}

func defaultDataPath() string {
	if env := os.Getenv("BESTDNS_DATA"); env != "" {
		return env
	}
	if runtime.GOOS == "windows" {
		return filepath.Join("data", "state.json")
	}
	return "/var/lib/bestdns/state.json"
}

func newLogger(debug bool) *slog.Logger {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
}

func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	dataPath := fs.String("data", defaultDataPath(), "state file path")
	dnsAddr := fs.String("dns", ":53", "DNS listen address (udp+tcp)")
	panelAddr := fs.String("panel", ":8080", "panel listen address")
	publicIP := fs.String("public-ip", "", "override advertised proxy address")
	proxyPorts := fs.String("proxy-ports", "", "comma separated relay ports (overrides settings, for testing)")
	allowAll := fs.Bool("allow-all", false, "serve unregistered clients")
	debug := fs.Bool("debug", false, "verbose logging")
	_ = fs.Parse(args)

	log := newLogger(*debug)
	log.Info("starting", "version", version, "data", *dataPath)

	st, err := store.Open(*dataPath)
	if err != nil {
		log.Error("cannot open state", "err", err)
		os.Exit(1)
	}

	// First run: mint a random password and print it once.
	if !st.HasPassword() {
		pw := store.GeneratePassword()
		if err := st.SetPassword(pw, true); err != nil {
			log.Error("cannot set initial password", "err", err)
			os.Exit(1)
		}
		path := panel.WriteInitialPassword(*dataPath, pw)
		line := strings.Repeat("─", 48)
		fmt.Printf("\n┌%s┐\n", line)
		fmt.Printf("│  BESTPRIME DNS — first run%-24s│\n", "")
		fmt.Printf("│  panel password: %-30s│\n", pw)
		if path != "" {
			fmt.Printf("│  saved to: %-36s│\n", path)
		}
		fmt.Printf("└%s┘\n\n", line)
	}
	if *allowAll {
		if _, err := st.UpdateSettings(func(s *store.Settings) error {
			s.AllowAll = true
			return nil
		}); err != nil {
			log.Warn("could not persist allow_all", "err", err)
		}
	}

	settings := st.Settings()
	if *proxyPorts != "" {
		var ports []int
		for _, part := range strings.Split(*proxyPorts, ",") {
			if n, err := strconv.Atoi(strings.TrimSpace(part)); err == nil && n > 0 && n < 65536 {
				ports = append(ports, n)
			}
		}
		if len(ports) > 0 {
			settings.ProxyPorts = ports
		}
	}
	stats := metrics.New()
	dnsSrv := dnsrv.New(st, stats, log)
	if *publicIP != "" {
		dnsSrv.SetPublicIP(*publicIP)
	} else if settings.ProxyIP != "" {
		dnsSrv.SetPublicIP(settings.ProxyIP)
	}
	go dnsSrv.DetectPublicIP()

	px := proxy.New(st, stats, log, dnsSrv, settings.MaxConns)
	if err := px.Listen(settings.ProxyPorts); err != nil {
		log.Error("proxy listeners", "err", err)
	}

	panelSrv := panel.New(st, stats, dnsSrv, px, log, version)

	dohAddr := ""
	if settings.DoHPort != "" {
		dohAddr = settings.DoHPort
		if !strings.HasPrefix(dohAddr, ":") {
			dohAddr = ":" + dohAddr
		}
	}
	udpAddr := *dnsAddr
	tcpAddr := *dnsAddr
	if err := dnsSrv.Listen(udpAddr, tcpAddr, dohAddr); err != nil {
		log.Error("dns listeners", "err", err)
		os.Exit(1)
	}

	errCh := make(chan error, 1)
	go func() {
		if err := panelSrv.ListenAndServe(*panelAddr); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	printBanner(log, *panelAddr, dnsSrv.PublicIP(), settings.ProxyPorts, st)

	// Periodic persistence: usage deltas every 15s, dirty state every 30s.
	flushDone := make(chan struct{})
	go func() {
		usageTick := time.NewTicker(15 * time.Second)
		saveTick := time.NewTicker(30 * time.Second)
		defer usageTick.Stop()
		defer saveTick.Stop()
		for {
			select {
			case <-usageTick.C:
				if usage := stats.DrainUsage(); len(usage) > 0 {
					counter := make(map[string]store.Counter, len(usage))
					for id, u := range usage {
						counter[id] = store.Counter{Bytes: u.Bytes, Queries: u.Queries, LastSeen: u.Seen}
					}
					st.AddUsage(counter)
				}
			case <-saveTick.C:
				if st.Dirty() {
					if err := st.Save(); err != nil {
						log.Error("state save failed", "err", err)
					}
				}
			case <-flushDone:
				if usage := stats.DrainUsage(); len(usage) > 0 {
					counter := make(map[string]store.Counter, len(usage))
					for id, u := range usage {
						counter[id] = store.Counter{Bytes: u.Bytes, Queries: u.Queries, LastSeen: u.Seen}
					}
					st.AddUsage(counter)
				}
				if err := st.Save(); err != nil {
					log.Error("final state save failed", "err", err)
				}
				return
			}
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-errCh:
		log.Error("panel failed", "err", err)
	}
	close(flushDone)
	_ = panelSrv.Close()
	dnsSrv.Close()
	px.Close()
	time.Sleep(150 * time.Millisecond)
}

func printBanner(log *slog.Logger, panelAddr, publicIP string, ports []int, st *store.Store) {
	host := detectHostIP()
	panelPort := portOf(panelAddr, "8080")
	dnsIP := publicIP
	if dnsIP == "" {
		dnsIP = host
	}
	portList := make([]string, 0, len(ports))
	for _, p := range ports {
		portList = append(portList, strconv.Itoa(p))
	}
	log.Info("ready",
		"panel", fmt.Sprintf("http://%s:%s/", host, panelPort),
		"dns", dnsIP,
		"relay_ports", strings.Join(portList, ","),
		"state", st.Path(),
	)
}

func detectHostIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}
	return "127.0.0.1"
}

func portOf(addr, fallback string) string {
	if _, port, err := net.SplitHostPort(addr); err == nil && port != "" {
		return port
	}
	if strings.HasPrefix(addr, ":") {
		return strings.TrimPrefix(addr, ":")
	}
	return fallback
}

func runPasswd(args []string) {
	fs := flag.NewFlagSet("passwd", flag.ExitOnError)
	dataPath := fs.String("data", defaultDataPath(), "state file path")
	_ = fs.Parse(args)

	st, err := store.Open(*dataPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot open %s: %v\n", *dataPath, err)
		os.Exit(1)
	}
	pw := ""
	if len(fs.Args()) > 0 {
		pw = strings.TrimSpace(fs.Args()[0])
	}
	if pw == "" {
		pw = store.GeneratePassword()
		fmt.Printf("generated password: %s\n", pw)
	}
	if err := st.SetPassword(pw, false); err != nil {
		fmt.Fprintf(os.Stderr, "cannot set password: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("password updated")
}
