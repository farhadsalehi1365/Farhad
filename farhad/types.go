package main

import "time"

const (
	AppName    = "Farhad"
	AppVersion = "v1.0"

	MaxTargets   = 5_000_000
	HeapLimit    = 1000
	Phase1MaxRTT = 800.0 // ms — phase-1 fast filter threshold
	Phase1Samps  = 2     // quick reachability samples in phase 1

	BenchBytes          = 25_000_000 // 25 MB download payload
	BenchCandidates     = 30
	BenchWorkers        = 8
)

// Config holds all tunable parameters. Safe to read under stateMu.RLock().
type Config struct {
	Threads      int
	PingCount    int
	Timeout      time.Duration
	TLSTimeout   time.Duration
	Ports        []int
	CIDRList     []string
	IPRanges     []string
	MaxDisplay   int
	MinScore     float64
	EnableTLS    bool
	EnableHTTP   bool
	EnableBench  bool
	Phase1MaxRTT float64

	// Probe target: the host/SNI/path used to talk to the Cloudflare edge
	// behind each candidate IP. Defaults to speed.cloudflare.com.
	SNI   string
	Host  string
	Path  string

	ConfigURL string
}

// CFEvidence is gathered from HTTP response headers/body to confirm the IP is
// really a Cloudflare edge (not just any open port).
type CFEvidence struct {
	CFRay    bool
	ServerCF bool
	Colo     string
}

func (e CFEvidence) IsCloudflare() bool {
	return e.CFRay || e.ServerCF || e.Colo != ""
}

// Result is a single measured (ip, port) target.
type Result struct {
	IP          string  `json:"ip"`
	Port        int     `json:"port"`
	Latency     float64 `json:"latency_ms"` // min RTT (headline)
	MinLat      float64 `json:"min_ms"`
	MaxLat      float64 `json:"max_ms"`
	Jitter      float64 `json:"jitter_ms"`
	Loss        float64 `json:"loss_pct"`
	Samples     int     `json:"samples"`
	TLS13       bool    `json:"tls13"`
	TLSVer      string  `json:"tls"`
	HTTP2       bool    `json:"http2"`
	Colo        string  `json:"colo"`
	IsCF        bool    `json:"is_cf"`
	DownloadMBs float64 `json:"download_mbs,omitempty"`
	ConnScore   float64 `json:"conn_score"`
	Score       float64 `json:"score"`
}

type Checkpoint struct {
	Timestamp string   `json:"timestamp"`
	Done      int64    `json:"done"`
	Total     int64    `json:"total"`
	Results   []Result `json:"results"`
}

// Phase1Result is the lightweight output of the fast TCP reachability filter.
type Phase1Result struct {
	IP   string
	Port int
}

// ResultHeap is a min-heap by Score, used to keep the top-K results.
type ResultHeap []Result

func (h ResultHeap) Len() int            { return len(h) }
func (h ResultHeap) Less(i, j int) bool  { return h[i].Score < h[j].Score }
func (h ResultHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *ResultHeap) Push(x any)         { *h = append(*h, x.(Result)) }
func (h *ResultHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}
