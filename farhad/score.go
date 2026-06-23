package main

import "math"

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// computeConn scores connectivity: latency + jitter + loss, then applies
// HARD penalties when the node lacks the features that matter for a usable
// proxy edge (TLS 1.3, HTTP/2, real Cloudflare colo).
func computeConn(r Result) float64 {
	// latency: 10ms => 100, 150ms => 0
	latScore := clamp(100-(math.Max(0, r.Latency-10)/140)*100, 0, 100)
	// jitter: 0ms => 100, 60ms => 0
	jitScore := clamp(100-(r.Jitter/60)*100, 0, 100)
	// loss: 0% => 100, 30% => 0  (steep — loss kills a proxy)
	lossScore := clamp(100-(r.Loss/30)*100, 0, 100)

	conn := latScore*0.5 + jitScore*0.2 + lossScore*0.3

	// Feature penalties — the core fix. A node that negotiates no TLS 1.3,
	// no HTTP/2, or returns no colo is NOT a clean edge and must rank low.
	if !r.TLS13 {
		conn -= 25
	}
	if !r.HTTP2 {
		conn -= 15
	}
	if r.Colo == "" {
		conn -= 30
	}
	if r.Loss > 20 {
		conn -= 20
	}
	return clamp(conn, 0, 100)
}

// computeScore combines connectivity with log-scaled throughput when a
// benchmark has been run.
func computeScore(r Result, hasBench bool) float64 {
	conn := computeConn(r)
	if !hasBench || r.DownloadMBs <= 0 {
		return math.Round(conn*10) / 10
	}
	// throughput: log scale, 100 MB/s => ~100 pts
	dl := clamp(math.Log10(r.DownloadMBs+1)/math.Log10(101)*100, 0, 100)
	s := conn*0.6 + dl*0.4
	return math.Round(s*10) / 10
}
