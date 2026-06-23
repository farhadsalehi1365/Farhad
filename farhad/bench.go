package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"
)

// runBenchmark measures real download throughput for the top TLS nodes and
// folds it back into the score. Uses a 25 MB payload (not 1 MB) so the result
// reflects sustained speed rather than TCP slow-start.
func runBenchmark(ctx context.Context, results []Result) []Result {
	sec("🚀 SPEED BENCHMARK")

	updated := append([]Result(nil), results...)

	var idxs []int
	for i, r := range updated {
		if isTLSPort(r.Port) {
			idxs = append(idxs, i)
			if len(idxs) >= BenchCandidates {
				break
			}
		}
	}
	if len(idxs) == 0 {
		logInfo("No TLS nodes to benchmark.")
		return updated
	}

	type benchRes struct {
		idx  int
		mbps float64
	}
	jobs := make(chan int, len(idxs))
	out := make(chan benchRes, len(idxs))

	workers := BenchWorkers
	if workers > len(idxs) {
		workers = len(idxs)
	}

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				mbps := downloadOnce(ctx, updated[idx].IP, updated[idx].Port)
				out <- benchRes{idx, mbps}
			}
		}()
	}
	for _, idx := range idxs {
		jobs <- idx
	}
	close(jobs)
	go func() { wg.Wait(); close(out) }()

	for br := range out {
		updated[br.idx].DownloadMBs = br.mbps
		updated[br.idx].Score = computeScore(updated[br.idx], true)

		status := cRd + "✗" + cR
		if br.mbps >= 0.5 {
			status = cG + "✓" + cR
		}
		logInfo(fmt.Sprintf("%s  %-15s :%4d  →  %s%.2f MB/s%s  colo:%s%s%s",
			status, updated[br.idx].IP, updated[br.idx].Port,
			cY, br.mbps, cR, cC, updated[br.idx].Colo, cR))
	}

	sort.Slice(updated, func(i, j int) bool { return updated[i].Score > updated[j].Score })
	return updated
}

// downloadOnce streams BenchBytes from the official speed endpoint, pinning the
// connection to the candidate IP via SNI/Host = speed.cloudflare.com (any clean
// CF edge serves any CF-hosted domain, so this works per-IP).
func downloadOnce(ctx context.Context, ip string, port int) float64 {
	const sni = "speed.cloudflare.com"
	dialAddr := net.JoinHostPort(ip, strconv.Itoa(port))
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2", "http/1.1"},
		},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, dialAddr)
		},
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{Transport: tr, Timeout: 15 * time.Second}

	url := fmt.Sprintf("https://%s/__down?bytes=%d", sni, BenchBytes)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0
	}
	req.Host = sni

	t0 := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	n, err := io.Copy(io.Discard, resp.Body)
	elapsed := time.Since(t0).Seconds()
	if err != nil || elapsed <= 0 || n == 0 {
		return 0
	}
	return float64(n) / elapsed / 1e6
}
