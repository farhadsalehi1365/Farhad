package main

import (
	"container/heap"
	"context"
	"fmt"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type Task struct {
	IP   string
	Port int
}

// runScan executes the two-phase pipeline:
//   Phase 1 — fast TCP reachability filter (cheap, drops closed ports)
//   Phase 2 — full probe (TCP stats + TLS handshake + HTTP/colo)
// Results stream into a top-K min-heap, scored and sorted on the fly.
func runScan(parentCtx context.Context) {
	cfg := globalCfg

	tt := totalTasks(cfg)
	if tt == 0 {
		logErr("No valid IPv4 targets configured. Set a CIDR or range in [3].")
		return
	}
	if tt > MaxTargets {
		logErr(fmt.Sprintf("Target count %d exceeds limit %d.", tt, MaxTargets))
		return
	}

	sec("⚡ SCAN PIPELINE")
	logInfo(fmt.Sprintf("Targets   : %s%d%s", cY, tt, cR))
	logInfo(fmt.Sprintf("Workers   : %s%d%s", cY, cfg.Threads, cR))
	logInfo(fmt.Sprintf("Ports     : %s%v%s", cY, cfg.Ports, cR))
	logInfo(fmt.Sprintf("SNI/Host  : %s%s%s", cY, cfg.SNI, cR))
	logInfo(fmt.Sprintf("TLS check : %s%v%s", cY, cfg.EnableTLS, cR))
	logInfo(fmt.Sprintf("MinScore  : %s%.1f%s", cY, cfg.MinScore, cR))
	fmt.Println()

	scanActive.Store(true)
	defer scanActive.Store(false)

	scanCtx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	// IP generator
	ipCh := make(chan string, 2000)
	go streamIPs(scanCtx, cfg, ipCh)

	// (ip, port) task fan-out
	taskCh := make(chan Task, 5000)
	ports := sortedPorts(cfg)
	go func() {
		defer close(taskCh)
		for ip := range ipCh {
			for _, p := range ports {
				select {
				case taskCh <- Task{ip, p}:
				case <-scanCtx.Done():
					return
				}
			}
		}
	}()

	phase2Ch := make(chan Phase1Result, 1000)
	resCh := make(chan Result, HeapLimit*2)

	var doneN, foundN int64
	var bestBits atomic.Uint64

	// Phase 1 workers
	var wg1 sync.WaitGroup
	for i := 0; i < cfg.Threads; i++ {
		wg1.Add(1)
		go func() {
			defer wg1.Done()
			for task := range taskCh {
				if scanCtx.Err() != nil {
					return
				}
				min, _, _, _, loss, ok := probeTCP(scanCtx, task.IP, task.Port, Phase1Samps, cfg.Timeout)
				atomic.AddInt64(&doneN, 1)
				if ok && min <= cfg.Phase1MaxRTT && loss < 100 {
					select {
					case phase2Ch <- Phase1Result{task.IP, task.Port}:
					case <-scanCtx.Done():
						return
					}
				}
			}
		}()
	}
	go func() { wg1.Wait(); close(phase2Ch) }()

	// Phase 2 workers
	p2w := cfg.Threads / 2
	if p2w < 4 {
		p2w = 4
	}
	var wg2 sync.WaitGroup
	for i := 0; i < p2w; i++ {
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			for p1 := range phase2Ch {
				if scanCtx.Err() != nil {
					return
				}
				res, ok := probeFull(scanCtx, cfg, p1)
				if !ok || res.Score < cfg.MinScore {
					continue
				}
				select {
				case resCh <- res:
					atomic.AddInt64(&foundN, 1)
					for {
						old := bestBits.Load()
						if res.Score <= math.Float64frombits(old) {
							break
						}
						if bestBits.CompareAndSwap(old, math.Float64bits(res.Score)) {
							break
						}
					}
				case <-scanCtx.Done():
					return
				}
			}
		}()
	}
	go func() { wg2.Wait(); close(resCh) }()

	// Collector: top-K heap, guarded by heapMu so the UI can snapshot it.
	h := &ResultHeap{}
	heap.Init(h)
	var heapMu sync.Mutex
	collectorDone := make(chan struct{})
	go func() {
		defer close(collectorDone)
		for res := range resCh {
			heapMu.Lock()
			if h.Len() < HeapLimit {
				heap.Push(h, res)
			} else if res.Score > (*h)[0].Score {
				heap.Pop(h)
				heap.Push(h, res)
			}
			heapMu.Unlock()
		}
	}()

	// UI + checkpoint ticker
	start := time.Now()
	uiDone := make(chan struct{})
	go func() {
		defer close(uiDone)
		ticker := time.NewTicker(200 * time.Millisecond)
		saveTick := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		defer saveTick.Stop()
		for {
			select {
			case <-collectorDone:
				return
			case <-saveTick.C:
				heapMu.Lock()
				snap := append([]Result(nil), (*h)...)
				heapMu.Unlock()
				saveCheckpoint(atomic.LoadInt64(&doneN), tt, dedupByIP(snap))
			case <-ticker.C:
				done := atomic.LoadInt64(&doneN)
				found := atomic.LoadInt64(&foundN)
				best := math.Float64frombits(bestBits.Load())
				eta := formatETA(time.Since(start), done, tt)
				pct := 0.0
				if tt > 0 {
					pct = float64(done) / float64(tt) * 100
				}
				drawProgress(done, tt, pct, float64(found), best, eta)
			}
		}
	}()

	<-collectorDone
	<-uiDone
	fmt.Printf("\n\n")
	logOK(fmt.Sprintf("Scan complete — %s%d%s qualifying nodes.", cG, atomic.LoadInt64(&foundN), cR))

	heapMu.Lock()
	var final []Result
	for h.Len() > 0 {
		final = append(final, heap.Pop(h).(Result))
	}
	heapMu.Unlock()

	sort.Slice(final, func(i, j int) bool { return final[i].Score > final[j].Score })
	final = dedupByIP(final)

	if cfg.EnableBench && len(final) > 0 {
		final = runBenchmark(parentCtx, final)
	}

	stateMu.Lock()
	bestResults = final
	stateMu.Unlock()

	saveResults(final)
	printTable(final)
	printSummary(final)
}
