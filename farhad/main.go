package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	parseCLI()

	// Graceful shutdown on Ctrl+C / SIGTERM (the original tool lacked this).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	printBanner()

	// Auto-load previous results quietly so [2]/[8] work immediately.
	if b, err := os.ReadFile("farhad_results.json"); err == nil {
		var data []Result
		if json.Unmarshal(b, &data) == nil && len(data) > 0 {
			deduped := dedupByIP(data)
			stateMu.Lock()
			bestResults = deduped
			stateMu.Unlock()
			logInfo(fmt.Sprintf("Auto-loaded %s%d%s previous results. Press %s[2]%s to view.",
				cG, len(deduped), cR, cG, cR))
		}
	}

	for {
		if ctx.Err() != nil {
			fmt.Println()
			logOK("Farhad terminated.")
			return
		}
		printMenu()
		switch rl() {
		case "1":
			runScan(ctx)
		case "2":
			showResults()
		case "3":
			configureTargets()
		case "4":
			engineParams()
		case "5":
			setConfigURL()
		case "6":
			loadSession()
		case "7":
			exportMenu()
		case "8":
			runBenchmarkMenu(ctx)
		case "0", "q", "exit", "quit":
			fmt.Println()
			logOK("Farhad terminated.")
			return
		default:
			logErr("Unknown option. Pick a number from the panel.")
		}
	}
}
