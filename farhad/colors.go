package main

import (
	"fmt"
	"strings"
	"time"
)

// ANSI colors
const (
	cR  = "\033[0m"
	cB  = "\033[1m"
	cDm = "\033[2m"
	cRd = "\033[31m"
	cG  = "\033[32m"
	cY  = "\033[33m"
	cBl = "\033[34m"
	cM  = "\033[35m"
	cC  = "\033[36m"
)

const banner = `
  ███████╗ █████╗ ██╗  ██╗██████╗  ██████╗
   ██╔════╝██╔══██╗╚██╗██╔╝██╔══██╗██╔═══██╗
   █████╗  ███████║ ╚███╔╝ ██████╔╝██║   ██║
   ██╔══╝  ██╔══██║ ██╔██╗ ██╔══██╗██║   ██║
   ██║     ██║  ██║██╔╝ ██╗██████╔╝╚██████╔╝
   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝`

func printBanner() {
	fmt.Printf("%s%s%s\n", cC, banner, cR)
	fmt.Printf("  %s%s%s · Cloudflare Clean-IP Scanner  %s[%s]%s\n", cB, AppName, cR, cY, AppVersion, cR)
	fmt.Printf("  %sAccurate TLS 1.3 · HTTP/2 · Colo detection%s\n\n", cDm, cR)
}

func sec(title string) {
	fmt.Printf("\n%s┌─ %s%s%s %s──────────────────────────────────%s\n",
		cC, cB, title, cR, cC, cR)
}

func logOK(msg string)  { fmt.Printf("  %s[✓]%s %s\n", cG, cR, msg) }
func logErr(msg string) { fmt.Printf("  %s[✗]%s %s\n", cRd, cR, msg) }
func logInfo(msg string) {
	fmt.Printf("  %s[i]%s %s\n", cC, cR, msg)
}

func tcpColor(v float64) string {
	if v <= 0 {
		return ""
	}
	if v > 200 {
		return cRd
	}
	if v > 100 {
		return cY
	}
	return cG
}

func lossColor(v float64) string {
	if v > 40 {
		return cRd
	}
	if v > 20 {
		return cY
	}
	return cG
}

func dlColor(v float64) string {
	if v >= 1 {
		return cG
	}
	if v >= 0.3 {
		return cY
	}
	if v > 0 {
		return cRd
	}
	return ""
}

func formatETA(elapsed time.Duration, done, total int64) string {
	if done <= 0 || total <= 0 || elapsed.Seconds() < 1 {
		return "ETA --:--"
	}
	rate := float64(done) / elapsed.Seconds()
	if rate <= 0 {
		return "ETA --:--"
	}
	rem := time.Duration(float64(total-done)/rate) * time.Second
	if rem > 99*time.Minute {
		return fmt.Sprintf("ETA %dh%02dm", int(rem.Hours()), int(rem.Minutes())%60)
	}
	return fmt.Sprintf("ETA %02d:%02d", int(rem.Minutes()), int(rem.Seconds())%60)
}

func drawProgress(done, total int64, pct, found, best float64, eta string) {
	barW := 24
	filled := int(pct / 100 * float64(barW))
	if filled > barW {
		filled = barW
	}
	bar := ""
	if filled > 0 {
		bar = cG + strings.Repeat("=", filled-1) + ">" + cR
	}
	bar += cDm + strings.Repeat("-", barW-filled) + cR
	fmt.Printf("\033[2K\r %s%d/%d%s [%s] ok:%s%d%s best:%s%.0f%s %s ",
		cY, done, total, cR, bar, cG, int(found), cR, cC, best, cR, eta)
}

func printTable(data []Result) {
	if len(data) == 0 {
		logErr("No results to display.")
		return
	}
	limit := globalCfg.MaxDisplay
	if limit > len(data) {
		limit = len(data)
	}

	hasBench := false
	for i := 0; i < limit; i++ {
		if data[i].DownloadMBs > 0 {
			hasBench = true
			break
		}
	}

	line := cC + strings.Repeat("─", 92) + cR
	fmt.Printf("\n%s\n", line)
	if hasBench {
		fmt.Printf("%s│ %-2s │ %-15s │ %-5s │ %-7s │ %-6s │ %-5s │ %-3s │ %-3s │ %-4s │ %-7s │ %-5s │%s\n",
			cC, "#", "IP", "Port", "Lat", "Jitter", "Loss%", "H2", "TLS", "Colo", "DL MB/s", "Score", cR)
	} else {
		fmt.Printf("%s│ %-2s │ %-15s │ %-5s │ %-7s │ %-6s │ %-5s │ %-3s │ %-3s │ %-4s │ %-5s │%s\n",
			cC, "#", "IP", "Port", "Lat", "Jitter", "Loss%", "H2", "TLS", "Colo", "Score", cR)
	}
	fmt.Printf("%s\n", line)

	for i := 0; i < limit; i++ {
		r := data[i]

		rankCol := cC
		switch {
		case i == 0:
			rankCol = cY + cB
		case i < 3:
			rankCol = cG
		}

		latStr := fmt.Sprintf("%.0fms", r.Latency)
		latCol := tcpColor(r.Latency)

		lossStr := fmt.Sprintf("%.0f%%", r.Loss)
		lossCol := lossColor(r.Loss)

		h2s, h2c := "NO ", cRd
		if r.HTTP2 {
			h2s, h2c = "YES", cG
		}

		tlss, tlsc := "---", cDm
		if globalCfg.EnableTLS {
			if r.TLS13 {
				tlss, tlsc = "1.3", cG
			} else if r.TLSVer != "" {
				tlss, tlsc = r.TLSVer, cY
			} else {
				tlss, tlsc = "1.2", cY
			}
		}

		colo := r.Colo
		if colo == "" {
			colo = "---"
		}

		fmt.Printf("%s│ %s%-2d%s │ %-15s │ %5d │ %s%7s%s │ %6.1f │ %s%5s%s │ %s%-3s%s │ %s%-3s%s │ %-4s │",
			cC, rankCol, i+1, cR, r.IP, r.Port,
			latCol, latStr, cR, r.Jitter,
			lossCol, lossStr, cR,
			h2c, h2s, cR, tlsc, tlss, cR, colo)
		if hasBench {
			fmt.Printf(" %s%6.2f%s │", dlColor(r.DownloadMBs), r.DownloadMBs, cR)
		}
		fmt.Printf(" %s%.1f%s\n", cG, r.Score, cR)
	}
	fmt.Printf("%s\n", line)
	logInfo(fmt.Sprintf("Showing %d/%d  ·  saved → %sfarhad_results.json%s", limit, len(data), cY, cR))
}

func printSummary(data []Result) {
	if len(data) == 0 {
		return
	}
	best := data[0]
	fmt.Printf("\n%s╔════════════════ SUMMARY ════════════════╗%s\n", cC, cR)
	fmt.Printf("%s║%s  🥇 Best   : %s%-15s%s :%d\n", cC, cR, cY, best.IP, cR, best.Port)

	coloCnt := map[string]int{}
	for _, r := range data {
		if r.Colo != "" {
			coloCnt[r.Colo]++
		}
	}
	topColo, topN := "", 0
	for c, n := range coloCnt {
		if n > topN {
			topColo, topN = c, n
		}
	}
	if topColo != "" {
		fmt.Printf("%s║%s  🌍 Colo   : %s%s%s (%d nodes)\n", cC, cR, cG, topColo, cR, topN)
	}

	var sumLat, sumJit, sumScore float64
	h2, tls13 := 0, 0
	for _, r := range data {
		sumLat += r.Latency
		sumJit += r.Jitter
		sumScore += r.Score
		if r.HTTP2 {
			h2++
		}
		if r.TLS13 {
			tls13++
		}
	}
	n := float64(len(data))
	fmt.Printf("%s║%s  📡 Lat    : %s%.0fms%s (avg)\n", cC, cR, cY, sumLat/n, cR)
	fmt.Printf("%s║%s  📶 Jitter : %s%.1fms%s (avg)\n", cC, cR, cY, sumJit/n, cR)
	fmt.Printf("%s║%s  ⭐ Score  : %s%.1f%s (avg)\n", cC, cR, cG, sumScore/n, cR)
	fmt.Printf("%s║%s  🔒 TLS1.3 : %s%d/%d%s\n", cC, cR, cG, tls13, len(data), cR)
	fmt.Printf("%s║%s  ⚡ HTTP/2 : %s%d/%d%s\n", cC, cR, cG, h2, len(data), cR)
	fmt.Printf("%s╚════════════════════════════════════════╝%s\n", cC, cR)
}
