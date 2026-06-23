package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// isTLSPort reports whether a port is expected to speak TLS.
// 80/8080/2052/2082/2086/2095 are plain HTTP on Cloudflare.
func isTLSPort(port int) bool {
	switch port {
	case 443, 8443, 2053, 2083, 2087, 2096:
		return true
	}
	return false
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "1.3"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS10:
		return "1.0"
	default:
		return "?"
	}
}

// probeTCP measures TCP connect RTT. Returns min/avg/max, jitter (mean absolute
// deviation), loss %, and ok=false if the port never answered.
func probeTCP(ctx context.Context, ip string, port, count int, timeout time.Duration) (min, avg, max, jitter, loss float64, ok bool) {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	samples := make([]float64, 0, count)
	failed := 0

	for i := 0; i < count; i++ {
		select {
		case <-ctx.Done():
			return
		default:
		}
		t0 := time.Now()
		conn, err := net.DialTimeout("tcp", addr, timeout)
		d := time.Since(t0).Seconds() * 1000
		if err != nil {
			failed++
			continue
		}
		conn.Close()
		samples = append(samples, d)
	}

	if len(samples) == 0 {
		loss = 100
		return
	}
	min = samples[0]
	max = samples[0]
	sum := 0.0
	for _, s := range samples {
		if s < min {
			min = s
		}
		if s > max {
			max = s
		}
		sum += s
	}
	avg = sum / float64(len(samples))

	mad := 0.0
	for _, s := range samples {
		mad += math.Abs(s - avg)
	}
	jitter = mad / float64(len(samples))
	loss = float64(failed) / float64(count) * 100
	ok = true
	return
}

// probeTLS performs a PURE TLS handshake against ip:port (independent of HTTP).
// This is the key fix: TLS version + ALPN (HTTP/2) come straight from the
// handshake's ConnectionState, so they are correct even when the HTTP trace
// request itself is blocked or mangled.
func probeTLS(ctx context.Context, ip string, port int, sni string, timeout time.Duration) (version uint16, alpn string, ok bool) {
	if sni == "" {
		sni = "speed.cloudflare.com"
	}
	dialer := &net.Dialer{Timeout: timeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return 0, "", false
	}
	defer rawConn.Close()

	_ = rawConn.SetDeadline(time.Now().Add(timeout))
	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         sni,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // we only care about the negotiated protocol
		NextProtos:         []string{"h2", "http/1.1"},
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return 0, "", false
	}
	st := tlsConn.ConnectionState()
	return st.Version, st.NegotiatedProtocol, true
}

// probeHTTP talks to the Cloudflare edge behind ip:port using the given Host/SNI
// and reads the datacenter (colo) from BOTH the CF-RAY header and the trace body.
// When TLS is used, the negotiated version/ALPN are returned too.
func probeHTTP(ctx context.Context, ip string, port int, host, path string, useTLS bool, sni string, timeout time.Duration) (colo string, ev CFEvidence, st *tls.ConnectionState, proto string, ok bool) {
	dialAddr := net.JoinHostPort(ip, strconv.Itoa(port))
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2", "http/1.1"},
		},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: timeout}).DialContext(ctx, network, dialAddr)
		},
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{Transport: tr, Timeout: timeout}

	scheme := "https"
	if !useTLS {
		scheme = "http"
	}
	u := fmt.Sprintf("%s://%s%s", scheme, host, path)
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return
	}
	req.Host = host

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	proto = resp.Proto
	if useTLS {
		st = resp.TLS // *tls.ConnectionState (nil if handshake-less)
	}

	// CF-RAY header, e.g. "8abc123f4-LHR"  =>  colo LHR
	ray := resp.Header.Get("Cf-Ray")
	if ray == "" {
		ray = resp.Header.Get("CF-RAY")
	}
	if ray != "" {
		ev.CFRay = true
		if idx := strings.LastIndex(ray, "-"); idx != -1 {
			colo = strings.ToUpper(strings.TrimSpace(ray[idx+1:]))
		}
	}
	if server := resp.Header.Get("Server"); strings.Contains(strings.ToLower(server), "cloudflare") {
		ev.ServerCF = true
	}

	// body fallback: colo=XXX in /cdn-cgi/trace
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if c := extractField(string(body), "colo"); c != "" {
		c = strings.ToUpper(strings.TrimSpace(c))
		if colo == "" {
			colo = c
		}
	}
	if colo != "" {
		ev.Colo = colo
	}
	ok = true
	return
}

func extractField(body, key string) string {
	k := key + "="
	idx := strings.Index(body, k)
	if idx == -1 {
		return ""
	}
	rest := body[idx+len(k):]
	end := strings.IndexAny(rest, "\r\n")
	if end == -1 {
		return rest
	}
	return rest[:end]
}

// probeFull runs the full phase-2 measurement for one (ip, port):
//   1. detailed TCP RTT / jitter / loss
//   2. TLS handshake (version + ALPN), independent of HTTP
//   3. HTTP request for colo + CF evidence
// On non-TLS ports (80/8080) TLS is skipped — only HTTP runs.
func probeFull(ctx context.Context, cfg Config, p1 Phase1Result) (Result, bool) {
	r := Result{IP: p1.IP, Port: p1.Port}

	min, _, max, jit, loss, ok := probeTCP(ctx, p1.IP, p1.Port, cfg.PingCount, cfg.Timeout)
	if !ok {
		return r, false
	}
	r.MinLat, r.MaxLat = min, max
	r.Latency = min // headline = best RTT (min sample)
	r.Jitter = jit
	r.Loss = loss
	r.Samples = cfg.PingCount

	useTLS := cfg.EnableTLS && isTLSPort(p1.Port)

	// Try HTTP first: on success it gives colo + (if TLS) version/ALPN.
	if cfg.EnableHTTP {
		colo, ev, st, proto, hok := probeHTTP(ctx, p1.IP, p1.Port, cfg.Host, cfg.Path, useTLS, cfg.SNI, cfg.Timeout)
		if hok {
			r.Colo = colo
			r.IsCF = ev.IsCloudflare()
			if useTLS && st != nil {
				r.TLS13 = st.Version == tls.VersionTLS13
				r.TLSVer = tlsVersionString(st.Version)
				r.HTTP2 = st.NegotiatedProtocol == "h2"
			}
			if !r.HTTP2 && strings.HasPrefix(proto, "HTTP/2") {
				r.HTTP2 = true
			}
		}
	}

	// Independent TLS handshake: needed when HTTP failed OR didn't yield TLS info.
	// This is what makes TLS/H2 detection reliable from restricted networks.
	if useTLS && r.TLSVer == "" {
		if ver, alpn, tok := probeTLS(ctx, p1.IP, p1.Port, cfg.SNI, cfg.TLSTimeout); tok {
			r.TLS13 = ver == tls.VersionTLS13
			r.TLSVer = tlsVersionString(ver)
			if alpn == "h2" {
				r.HTTP2 = true
			}
		}
	}

	r.ConnScore = computeConn(r)
	r.Score = computeScore(r, false)
	return r, true
}
