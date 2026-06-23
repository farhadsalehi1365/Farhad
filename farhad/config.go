package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var inputReader = bufio.NewReader(os.Stdin)

func defaultThreads() int {
	n := runtime.NumCPU() * 4
	if n < 16 {
		n = 16
	}
	if n > 48 {
		n = 48
	}
	return n
}

var (
	stateMu    sync.RWMutex
	bestResults []Result
	scanActive  atomic.Bool

	globalCfg = Config{
		Threads:      defaultThreads(),
		PingCount:    4,
		Timeout:      2500 * time.Millisecond,
		TLSTimeout:   1500 * time.Millisecond,
		Ports:        []int{443, 8443, 2053, 2083, 2087, 2096},
		CIDRList:     []string{"104.16.0.0/24"},
		IPRanges:     []string{},
		MaxDisplay:   15,
		MinScore:     40.0,
		EnableTLS:    true,
		EnableHTTP:   true,
		EnableBench:  false,
		Phase1MaxRTT: Phase1MaxRTT,
		SNI:          "speed.cloudflare.com",
		Host:         "speed.cloudflare.com",
		Path:         "/cdn-cgi/trace",
	}
)

// rl reads a trimmed line from stdin.
func rl() string {
	l, _ := inputReader.ReadString('\n')
	return strings.TrimSpace(l)
}

func splitTrim(s, sep string) []string {
	var out []string
	for _, p := range strings.Split(s, sep) {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseCLI() {
	threads := flag.Int("threads", defaultThreads(), "concurrent workers")
	timeout := flag.Int("timeout", 2500, "TCP timeout ms")
	tlsTO := flag.Int("tls-timeout", 1500, "TLS handshake timeout ms")
	pings := flag.Int("pings", 4, "TCP samples per target (phase 2)")
	minScore := flag.Float64("min-score", 40.0, "minimum score 0-100")
	cidr := flag.String("cidr", "", "comma-separated CIDRs")
	rng := flag.String("range", "", "IP range a.b.c.d-a.b.c.e")
	ports := flag.String("ports", "", "comma-separated ports")
	bench := flag.Bool("bench", false, "run speed benchmark on top nodes")
	noTLS := flag.Bool("no-tls", false, "skip TLS check")
	noHTTP := flag.Bool("no-http", false, "skip HTTP/colo check")
	sni := flag.String("sni", "", "TLS SNI and Host header")
	cfgURL := flag.String("url", "", "VLESS/Trojan config URL")
	ver := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *ver {
		fmt.Printf("%s %s\n", AppName, AppVersion)
		os.Exit(0)
	}

	if *threads > 0 {
		globalCfg.Threads = *threads
	}
	if *timeout > 0 {
		globalCfg.Timeout = time.Duration(*timeout) * time.Millisecond
	}
	if *tlsTO > 0 {
		globalCfg.TLSTimeout = time.Duration(*tlsTO) * time.Millisecond
	}
	if *pings > 0 {
		globalCfg.PingCount = *pings
	}
	if *minScore >= 0 {
		globalCfg.MinScore = *minScore
	}
	if *cidr != "" {
		globalCfg.CIDRList = splitTrim(*cidr, ",")
		globalCfg.IPRanges = []string{}
	}
	if *rng != "" {
		globalCfg.IPRanges = []string{*rng}
	}
	if *ports != "" {
		var ps []int
		for _, p := range splitTrim(*ports, ",") {
			if n, err := strconv.Atoi(p); err == nil && n > 0 && n < 65536 {
				ps = append(ps, n)
			}
		}
		if len(ps) > 0 {
			globalCfg.Ports = ps
		}
	}
	if *sni != "" {
		globalCfg.SNI = *sni
		globalCfg.Host = *sni
	}
	if *cfgURL != "" {
		applyConfigURL(*cfgURL)
	}
	globalCfg.EnableBench = *bench
	if *noTLS {
		globalCfg.EnableTLS = false
	}
	if *noHTTP {
		globalCfg.EnableHTTP = false
	}
}

// applyConfigURL parses a VLESS or Trojan URL and configures SNI/Host/Path/Port.
func applyConfigURL(raw string) {
	host, path, port, useTLS := parseConfigURL(raw)
	if host == "" {
		logErr("Could not parse config URL.")
		return
	}
	stateMu.Lock()
	globalCfg.SNI = host
	globalCfg.Host = host
	if path != "" {
		globalCfg.Path = path
	}
	if port > 0 {
		found := false
		for _, p := range globalCfg.Ports {
			if p == port {
				found = true
				break
			}
		}
		if !found {
			globalCfg.Ports = append([]int{port}, globalCfg.Ports...)
		}
	}
	stateMu.Unlock()
	logOK(fmt.Sprintf("Config → Host:%s%s%s  Path:%s%s%s  Port:%s%d%s  TLS:%s%v%s",
		cY, host, cR, cY, path, cR, cY, port, cR, cY, useTLS, cR))
}

// parseConfigURL extracts host/sni, path, port and TLS flag from a share link.
// Works with vless://...?sni=..&... and trojan://password@host:port?...
func parseConfigURL(raw string) (host, path string, port int, useTLS bool) {
	if idx := strings.Index(raw, "#"); idx != -1 {
		raw = raw[:idx] // drop fragment label
	}
	u, err := url.Parse(raw)
	if err != nil {
		return
	}
	scheme := strings.ToLower(u.Scheme)
	q := u.Query()

	// host/sni: prefer the sni/host query param, fall back to the address
	host = q.Get("sni")
	if host == "" {
		host = q.Get("host")
	}
	if host == "" {
		host = u.Hostname()
	}
	host = strings.ToLower(strings.TrimSpace(host))

	path = q.Get("path")
	if path == "" {
		path = "/"
	}
	if dec, err := url.QueryUnescape(path); err == nil {
		path = dec
	}

	if portStr := u.Port(); portStr != "" {
		if n, err := strconv.Atoi(portStr); err == nil {
			port = n
		}
	}

	security := strings.ToLower(q.Get("security"))
	useTLS = security == "tls" || scheme == "trojan" ||
		port == 443 || port == 8443 || port == 2053 ||
		port == 2083 || port == 2087 || port == 2096
	return
}
