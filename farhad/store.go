package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// atomicWrite writes to a temp file then renames — crash-safe.
func atomicWrite(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func saveResults(data []Result) {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return
	}
	_ = atomicWrite("farhad_results.json", b)
}

func saveCheckpoint(done, total int64, data []Result) {
	cp := Checkpoint{
		Timestamp: time.Now().Format(time.RFC3339),
		Done:      done,
		Total:     total,
		Results:   data,
	}
	b, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return
	}
	_ = atomicWrite("farhad_checkpoint.json", b)
}

// dedupByIP keeps the best-scoring result per IP and re-sorts by score.
func dedupByIP(results []Result) []Result {
	seen := make(map[string]int)
	var out []Result
	for _, r := range results {
		if idx, ok := seen[r.IP]; ok {
			if r.Score > out[idx].Score {
				out[idx] = r
			}
		} else {
			seen[r.IP] = len(out)
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out
}

func loadSession() {
	sec("📥 LOAD SESSION")
	if b, err := os.ReadFile("farhad_checkpoint.json"); err == nil {
		var cp Checkpoint
		if json.Unmarshal(b, &cp) == nil && len(cp.Results) > 0 {
			deduped := dedupByIP(cp.Results)
			stateMu.Lock()
			bestResults = deduped
			stateMu.Unlock()
			pct := 0.0
			if cp.Total > 0 {
				pct = float64(cp.Done) / float64(cp.Total) * 100
			}
			logOK(fmt.Sprintf("Checkpoint : %s%s%s", cY, cp.Timestamp, cR))
			logOK(fmt.Sprintf("Progress   : %s%d/%d (%.1f%%)%s", cY, cp.Done, cp.Total, pct, cR))
			logOK(fmt.Sprintf("Results    : %s%d nodes%s", cG, len(deduped), cR))
			printTable(deduped)
			return
		}
	}
	if b, err := os.ReadFile("farhad_results.json"); err == nil {
		var data []Result
		if json.Unmarshal(b, &data) == nil && len(data) > 0 {
			deduped := dedupByIP(data)
			stateMu.Lock()
			bestResults = deduped
			stateMu.Unlock()
			logOK(fmt.Sprintf("Loaded %s%d%s results from last run.", cG, len(deduped), cR))
			printTable(deduped)
			return
		}
	}
	logErr("No checkpoint or saved session found.")
}

func exportMenu() {
	sec("💾 EXPORT")
	stateMu.RLock()
	data := append([]Result(nil), bestResults...)
	stateMu.RUnlock()
	if len(data) == 0 {
		logErr("No data — run a scan first.")
		return
	}
	fmt.Printf("  %s[1]%s JSON   %s[2]%s CSV   %s[3]%s TXT   %s[0]%s Cancel\n  %s›%s ",
		cG, cR, cG, cR, cG, cR, cRd, cR, cC, cR)

	switch rl() {
	case "1":
		b, _ := json.MarshalIndent(data, "", "  ")
		_ = atomicWrite("farhad_export.json", b)
		logOK(fmt.Sprintf("Saved → %sfarhad_export.json%s (%d nodes)", cY, cR, len(data)))
	case "2":
		var b strings.Builder
		b.WriteString("IP,Port,Latency_ms,Min_ms,Max_ms,Jitter_ms,Loss_pct,TLS,HTTP2,Colo,Download_MBs,ConnScore,Score\n")
		for _, r := range data {
			fmt.Fprintf(&b, "%s,%d,%.1f,%.1f,%.1f,%.2f,%.1f,%s,%v,%s,%.2f,%.1f,%.1f\n",
				r.IP, r.Port, r.Latency, r.MinLat, r.MaxLat, r.Jitter, r.Loss,
				r.TLSVer, r.HTTP2, r.Colo, r.DownloadMBs, r.ConnScore, r.Score)
		}
		_ = atomicWrite("farhad_export.csv", []byte(b.String()))
		logOK(fmt.Sprintf("Saved → %sfarhad_export.csv%s (%d nodes)", cY, cR, len(data)))
	case "3":
		var b strings.Builder
		for _, r := range data {
			fmt.Fprintf(&b, "%s:%d\n", r.IP, r.Port)
		}
		_ = atomicWrite("farhad_export.txt", []byte(b.String()))
		logOK(fmt.Sprintf("Saved → %sfarhad_export.txt%s (%d nodes)", cY, cR, len(data)))
	}
}
