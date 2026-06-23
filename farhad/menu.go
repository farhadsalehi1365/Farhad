package main

import (
	"context"
	"fmt"
	"strconv"
	"time"
)

func printMenu() {
	fmt.Printf("\n%s╔══════════════════════════════════════╗%s\n", cC, cR)
	fmt.Printf("%s║  %s%s — CONTROL PANEL%s                   %s║%s\n", cC, cB, AppName, cR, cC, cR)
	fmt.Printf("%s╠══════════════════════════════════════╣%s\n", cC, cR)
	fmt.Printf("%s║%s  %s[1]%s ⚡  Launch Scan                  %s║%s\n", cC, cR, cG, cR, cC, cR)
	fmt.Printf("%s║%s  %s[2]%s 📊  Show Results                 %s║%s\n", cC, cR, cG, cR, cC, cR)
	fmt.Printf("%s║%s  %s[3]%s 📡  Configure Targets            %s║%s\n", cC, cR, cY, cR, cC, cR)
	fmt.Printf("%s║%s  %s[4]%s 🛠️   Engine Parameters            %s║%s\n", cC, cR, cY, cR, cC, cR)
	fmt.Printf("%s║%s  %s[5]%s 🔗  Set Config URL               %s║%s\n", cC, cR, cM, cR, cC, cR)
	fmt.Printf("%s║%s  %s[6]%s 📥  Load Session                 %s║%s\n", cC, cR, cBl, cR, cC, cR)
	fmt.Printf("%s║%s  %s[7]%s 💾  Export Results               %s║%s\n", cC, cR, cBl, cR, cC, cR)
	fmt.Printf("%s║%s  %s[8]%s 🚀  Speed Benchmark (Top %2d)     %s║%s\n", cC, cR, cM, cR, BenchCandidates, cC, cR)
	fmt.Printf("%s║%s  %s[0]%s 🛑  Exit                         %s║%s\n", cC, cR, cRd, cR, cC, cR)
	fmt.Printf("%s╚══════════════════════════════════════╝%s\n", cC, cR)
	fmt.Printf("  %s›%s ", cC, cR)
}

func showResults() {
	sec("📊 RESULTS")
	stateMu.RLock()
	data := append([]Result(nil), bestResults...)
	stateMu.RUnlock()
	if len(data) == 0 {
		logErr("No results yet — run a scan first.")
		return
	}
	printTable(data)
	printSummary(data)
}

func configureTargets() {
	sec("📡 CONFIGURE TARGETS")
	stateMu.RLock()
	fmt.Printf("  CIDRs : %s%v%s\n", cY, globalCfg.CIDRList, cR)
	fmt.Printf("  Range : %s%v%s\n", cY, globalCfg.IPRanges, cR)
	fmt.Printf("  Ports : %s%v%s\n", cY, globalCfg.Ports, cR)
	stateMu.RUnlock()

	fmt.Printf("\n  %s[1]%s CIDR  %s[2]%s Range  %s[3]%s Ports  %s[0]%s Back\n  %s›%s ",
		cG, cR, cG, cR, cG, cR, cRd, cR, cC, cR)
	switch rl() {
	case "1":
		fmt.Printf("  CIDRs (comma-sep): ")
		cidrs := splitTrim(rl(), ",")
		if len(cidrs) > 0 {
			stateMu.Lock()
			globalCfg.CIDRList = cidrs
			globalCfg.IPRanges = []string{}
			stateMu.Unlock()
			logOK(fmt.Sprintf("CIDRs → %v", cidrs))
		}
	case "2":
		fmt.Printf("  Range (a.b.c.d-a.b.c.e): ")
		input := rl()
		if input != "" {
			stateMu.Lock()
			globalCfg.IPRanges = []string{input}
			stateMu.Unlock()
			logOK(fmt.Sprintf("Range → %s", input))
		}
	case "3":
		fmt.Printf("  Ports (comma-sep): ")
		var ports []int
		for _, p := range splitTrim(rl(), ",") {
			if n, err := strconv.Atoi(p); err == nil && n > 0 && n < 65536 {
				ports = append(ports, n)
			}
		}
		if len(ports) > 0 {
			stateMu.Lock()
			globalCfg.Ports = ports
			stateMu.Unlock()
			logOK(fmt.Sprintf("Ports → %v", ports))
		}
	}
}

func engineParams() {
	sec("🛠️  ENGINE PARAMETERS")
	stateMu.RLock()
	cfg := globalCfg
	stateMu.RUnlock()

	fmt.Printf("  [1] Threads    : %s%d%s\n", cY, cfg.Threads, cR)
	fmt.Printf("  [2] Timeout    : %s%dms%s\n", cY, cfg.Timeout.Milliseconds(), cR)
	fmt.Printf("  [3] TLS Timeout: %s%dms%s\n", cY, cfg.TLSTimeout.Milliseconds(), cR)
	fmt.Printf("  [4] Pings      : %s%d%s\n", cY, cfg.PingCount, cR)
	fmt.Printf("  [5] MinScore   : %s%.1f%s\n", cY, cfg.MinScore, cR)
	fmt.Printf("  [6] TLS check  : %s%v%s\n", cY, cfg.EnableTLS, cR)
	fmt.Printf("  [7] HTTP check : %s%v%s\n", cY, cfg.EnableHTTP, cR)
	fmt.Printf("  [8] Benchmark  : %s%v%s\n", cY, cfg.EnableBench, cR)
	fmt.Printf("  %s[0]%s Back\n  %s›%s ", cRd, cR, cC, cR)

	switch rl() {
	case "1":
		fmt.Printf("  Threads [%d]: ", cfg.Threads)
		if n, err := strconv.Atoi(rl()); err == nil && n > 0 {
			stateMu.Lock()
			globalCfg.Threads = n
			stateMu.Unlock()
			logOK(fmt.Sprintf("Threads → %d", n))
		}
	case "2":
		fmt.Printf("  Timeout ms [%d]: ", cfg.Timeout.Milliseconds())
		if n, err := strconv.Atoi(rl()); err == nil && n > 0 {
			stateMu.Lock()
			globalCfg.Timeout = time.Duration(n) * time.Millisecond
			stateMu.Unlock()
			logOK(fmt.Sprintf("Timeout → %dms", n))
		}
	case "3":
		fmt.Printf("  TLS Timeout ms [%d]: ", cfg.TLSTimeout.Milliseconds())
		if n, err := strconv.Atoi(rl()); err == nil && n > 0 {
			stateMu.Lock()
			globalCfg.TLSTimeout = time.Duration(n) * time.Millisecond
			stateMu.Unlock()
			logOK(fmt.Sprintf("TLS Timeout → %dms", n))
		}
	case "4":
		fmt.Printf("  Pings [%d]: ", cfg.PingCount)
		if n, err := strconv.Atoi(rl()); err == nil && n > 0 {
			stateMu.Lock()
			globalCfg.PingCount = n
			stateMu.Unlock()
			logOK(fmt.Sprintf("Pings → %d", n))
		}
	case "5":
		fmt.Printf("  MinScore [%.1f]: ", cfg.MinScore)
		if f, err := strconv.ParseFloat(rl(), 64); err == nil {
			stateMu.Lock()
			globalCfg.MinScore = f
			stateMu.Unlock()
			logOK(fmt.Sprintf("MinScore → %.1f", f))
		}
	case "6":
		stateMu.Lock()
		globalCfg.EnableTLS = !globalCfg.EnableTLS
		v := globalCfg.EnableTLS
		stateMu.Unlock()
		logOK(fmt.Sprintf("TLS check → %v", v))
	case "7":
		stateMu.Lock()
		globalCfg.EnableHTTP = !globalCfg.EnableHTTP
		v := globalCfg.EnableHTTP
		stateMu.Unlock()
		logOK(fmt.Sprintf("HTTP check → %v", v))
	case "8":
		stateMu.Lock()
		globalCfg.EnableBench = !globalCfg.EnableBench
		v := globalCfg.EnableBench
		stateMu.Unlock()
		logOK(fmt.Sprintf("Benchmark → %v", v))
	}
}

func setConfigURL() {
	sec("🔗 SET CONFIG URL")
	stateMu.RLock()
	fmt.Printf("  Host  : %s%s%s\n", cY, globalCfg.Host, cR)
	fmt.Printf("  SNI   : %s%s%s\n", cY, globalCfg.SNI, cR)
	fmt.Printf("  Path  : %s%s%s\n", cY, globalCfg.Path, cR)
	fmt.Printf("  Ports : %s%v%s\n", cY, globalCfg.Ports, cR)
	stateMu.RUnlock()

	fmt.Printf("\n  Paste VLESS/Trojan URL (Enter to skip):\n  %s›%s ", cC, cR)
	input := rl()
	if input == "" {
		return
	}
	applyConfigURL(input)
}

func runBenchmarkMenu(ctx context.Context) {
	stateMu.RLock()
	data := append([]Result(nil), bestResults...)
	stateMu.RUnlock()
	if len(data) == 0 {
		logErr("No results — run a scan first.")
		return
	}
	updated := runBenchmark(ctx, data)
	stateMu.Lock()
	bestResults = updated
	stateMu.Unlock()
	saveResults(updated)
	printTable(updated)
	printSummary(updated)
}
