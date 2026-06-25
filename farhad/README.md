# 🛰️ Farhad — Cloudflare Clean-IP Scanner

**Farhad** is a fast, accurate terminal scanner that finds the best Cloudflare edge
IPs for your proxy configs (VLESS / Trojan / etc.). It measures **real latency,
jitter, packet loss, TLS 1.3, HTTP/2, datacenter (colo) and download speed**, then
ranks IPs by a transparent score.

It is the fixed successor to scanners whose `TLS / H2 / Colo` columns always came
back empty — because they tied TLS detection to the HTTP request. Farhad fixes
that at the root.

---

## ✨ What it fixes

| Problem (older tools) | How Farhad solves it |
|---|---|
| TLS 1.3 & HTTP/2 always `NO` / `1.2` | **TLS is detected from the handshake itself** (`ConnectionState().Version` + `NegotiatedProtocol`), fully independent of HTTP. |
| `colo=` always empty | Colo is read from **both** the `CF-RAY` header (`…-LHR`) and the `cdn-cgi/trace` body. |
| Port `80` tried a TLS handshake | Non-TLS ports run **HTTP only** — TLS is skipped automatically. |
| 60% loss still scored 70 | Loss is penalised hard (30% loss → connectivity zeroed). |
| Speed test used a tiny 1 MB payload | Benchmark streams **25 MB** so it reflects real throughput. |

---

## 🚀 Quick start (Termux)

```bash
# 1. install Go
pkg install golang git -y

# 2. clone
git clone https://github.com/farhadsalehi1365/farhad.git
cd farhad

# 3. build
go build -o farhad .

# 4. run
./farhad
```

That's it — you're in the control panel.

---

## 🧭 Usage

### Interactive menu
```
[1] ⚡ Launch Scan       [5] 🔗 Set Config URL
[2] 📊 Show Results      [6] 📥 Load Session
[3] 📡 Configure Targets [7] 💾 Export Results
[4] 🛠️  Engine Parameters [8] 🚀 Speed Benchmark (Top 30)
[0] 🛑 Exit
```

### From a config link (option 5)
Paste your VLESS / Trojan share link — Farhad extracts **host / SNI / path / port**
and uses them for probing. Example output:
```
Config → Host: your.host.com  Path: /ray  Port: 443  TLS: true
```

### Command-line flags
```bash
./farhad -cidr 104.16.0.0/20,172.64.0.0/20 -ports 443,2053 -bench
./farhad -range 104.16.0.1-104.16.0.254 -threads 64
./farhad -url "trojan://pass@host:443?security=tls&sni=host.com"
./farhad -sni speed.cloudflare.com -min-score 55 -pings 6
```

| Flag | Default | Description |
|---|---|---|
| `-cidr` | `104.16.0.0/24` | Comma-separated CIDRs |
| `-range` | — | `start-end` IPv4 range |
| `-ports` | `443,8443,2053,2083,2087,2096` | Ports to probe |
| `-threads` | `cpu*4` (16–48) | Concurrent workers |
| `-timeout` | `2500` ms | TCP timeout |
| `-tls-timeout` | `1500` ms | TLS handshake timeout |
| `-pings` | `4` | TCP samples per target |
| `-min-score` | `40` | Minimum score to keep |
| `-bench` | off | Benchmark top nodes after scan |
| `-sni` | `speed.cloudflare.com` | TLS SNI / Host header |
| `-url` | — | VLESS / Trojan config URL |
| `-no-tls` / `-no-http` | off | Skip a detection layer |

---

## 🏗️ Architecture

Two-phase concurrent pipeline with a top-K min-heap (no sorting the whole list):

```
CIDR/range ──► IP stream ──► (ip,port) tasks
                                   │
        ┌──────────────────────────┴───────────────┐
   Phase 1: fast TCP reachability filter (cheap)     │
   Phase 2: TCP stats + TLS handshake + HTTP/colo    │
        └──────────────────► top-K heap ◄ scored ◄──┘
                                   │
              optional speed benchmark (25 MB)
                                   │
                  JSON/CSV/TXT export + checkpoint
```

- **Phase 1** drops closed ports with a single cheap connect.
- **Phase 2** runs the detailed measurement, including the independent TLS
  handshake that makes detection reliable from restricted networks.
- **Checkpoint** auto-saves every 30s; resume anytime with `[6]`.
- **Ctrl+C** triggers a graceful shutdown.

### Files
| File | Responsibility |
|---|---|
| `probe.go` | TLS handshake, HTTP/colo detection — the core fix |
| `scan.go` | Two-phase pipeline, worker pool, top-K heap |
| `score.go` | Connectivity + throughput scoring |
| `bench.go` | Download speed benchmark |
| `ipgen.go` | CIDR/range expansion |
| `config.go` | Global config, CLI flags, config-URL parsing |
| `store.go` | Save / load / export, dedup |
| `colors.go` | Banner, table, summary, progress UI |
| `menu.go` | Interactive control panel |
| `types.go` | `Result`, `Config`, heap types |

---

## 📊 Scoring

```
conn = latency(0.5) + jitter(0.2) + loss(0.3)
       − 25 if no TLS 1.3
       − 15 if no HTTP/2
       − 30 if no colo (not a real CF edge)
       − 20 if loss > 20%

final = conn*0.6 + throughput(log-scaled)*0.4   (when benchmarked)
```

A node with no TLS 1.3, no HTTP/2, and no colo **cannot** rank high — exactly
what a clean-IP finder needs.

---

## ⚠️ Notes

- Detection probes use `InsecureSkipVerify` intentionally — we only read the
  negotiated protocol, not the certificate.
- The benchmark dials each candidate IP directly with SNI/Host
  `speed.cloudflare.com`; any clean Cloudflare edge serves it.
- Built and tested on **Termux (Android)** and Linux.

## License

MIT — do whatever you want. PRs welcome.
