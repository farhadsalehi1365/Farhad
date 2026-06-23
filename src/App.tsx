import { useState } from "react";

const FIXES = [
  {
    icon: "🔒",
    title: "TLS 1.3 / HTTP-2 detection",
    bad: "Always reported TLS 1.2 and H2 = NO.",
    good: "Read straight from the TLS handshake — independent of HTTP.",
  },
  {
    icon: "🌍",
    title: "Datacenter (colo)",
    bad: "colo= came back empty every time.",
    good: "Parsed from both the CF-RAY header and the trace body.",
  },
  {
    icon: "🔌",
    title: "Port 80 handling",
    bad: "Tried a TLS handshake on plain HTTP ports.",
    good: "Non-TLS ports run HTTP only — TLS is auto-skipped.",
  },
  {
    icon: "📉",
    title: "Packet-loss scoring",
    bad: "60% loss still scored 70.",
    good: "Loss is penalised hard — 30% zeroes connectivity.",
  },
  {
    icon: "⚡",
    title: "Throughput payload",
    bad: "Benchmarked a tiny 1 MB payload.",
    good: "Streams 25 MB so the number reflects real speed.",
  },
  {
    icon: "🎯",
    title: "Ranking you can trust",
    bad: "Best IP = lowest latency, nothing else.",
    good: "Latency + jitter + loss + TLS + H2 + colo + speed.",
  },
];

const STEPS = [
  { label: "Install Go + git", cmd: "pkg install golang git -y" },
  { label: "Clone the repo", cmd: "git clone https://github.com/you/farhad.git && cd farhad" },
  { label: "Build the binary", cmd: "go build -o farhad ." },
  { label: "Run it", cmd: "./farhad" },
];

const FLAGS = [
  ["-cidr", "104.16.0.0/24", "Comma-separated CIDRs"],
  ["-range", "—", "IPv4 range start-end"],
  ["-ports", "443,2053,8443", "Ports to probe"],
  ["-threads", "cpu*4", "Concurrent workers"],
  ["-pings", "4", "TCP samples per target"],
  ["-min-score", "40", "Minimum score to keep"],
  ["-bench", "off", "Benchmark top nodes"],
  ["-url", "—", "VLESS / Trojan config link"],
  ["-sni", "speed.cloudflare.com", "TLS SNI / Host"],
];

const ARCH = `CIDR / range ─► IP stream ─► (ip, port) tasks
        ┌────────────────────────────┴────────────────┐
   Phase 1   fast TCP reachability filter (cheap)
   Phase 2   TCP stats + TLS handshake + HTTP/colo
        └────────────────►  top-K heap  ◄── scored
                              │
            optional speed benchmark (25 MB)
                              │
              JSON / CSV / TXT  +  auto-checkpoint`;

function CodeBlock({ cmd }: { cmd: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="group relative">
      <pre className="overflow-x-auto rounded-lg border border-term-line bg-black/50 px-4 py-3 pr-12 font-mono text-[13px] text-green-400">
        <span className="select-none text-cyan">$ </span>
        {cmd}
      </pre>
      <button
        onClick={() => {
          navigator.clipboard?.writeText(cmd);
          setCopied(true);
          setTimeout(() => setCopied(false), 1200);
        }}
        className="absolute right-2 top-2 rounded border border-term-line bg-term-panel px-2 py-1 font-mono text-[10px] text-slate-400 transition hover:border-cyan/50 hover:text-cyan"
      >
        {copied ? "✓ copied" : "copy"}
      </button>
    </div>
  );
}

export default function App() {
  return (
    <div className="min-h-screen bg-term-bg text-slate-300">
      {/* Hero */}
      <header className="bg-grid scanline border-b border-term-line">
        <div className="mx-auto max-w-5xl px-5 py-16 sm:py-24">
          <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-cyan/30 bg-cyan/10 px-3 py-1 font-mono text-xs text-cyan">
            <span className="h-1.5 w-1.5 animate-pulse-glow rounded-full bg-cyan" />
            Cloudflare Clean-IP Scanner · v1.0
          </div>
          <h1 className="font-mono text-5xl font-bold tracking-tight text-slate-100 sm:text-7xl">
            Farhad
          </h1>
          <p className="mt-4 max-w-2xl font-mono text-base leading-relaxed text-slate-400 sm:text-lg">
            A fast, accurate terminal scanner that finds the best Cloudflare edge
            IPs for your proxy configs. It measures{" "}
            <span className="text-slate-200">real latency, jitter, loss, TLS 1.3,
            HTTP/2, colo and download speed</span> — and ranks IPs you can
            actually trust.
          </p>
          <div className="mt-7 flex flex-wrap gap-3">
            <a
              href="#start"
              className="rounded-lg bg-cyan px-5 py-2.5 font-mono text-sm font-bold text-black transition hover:bg-cyan/80"
            >
              ⚡ Quick start
            </a>
            <a
              href="#fixes"
              className="rounded-lg border border-term-line px-5 py-2.5 font-mono text-sm text-slate-300 transition hover:border-cyan/40 hover:text-cyan"
            >
              What it fixes
            </a>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-5xl px-5 py-14">
        {/* Fixes */}
        <section id="fixes" className="scroll-mt-6">
          <h2 className="font-mono text-sm font-semibold uppercase tracking-widest text-cyan">
            ── The root cause, fixed
          </h2>
          <p className="mt-2 max-w-2xl font-mono text-sm text-slate-400">
            Older scanners tied TLS detection to the HTTP request — so on
            restricted networks TLS, HTTP/2 and colo all came back empty. Farhad
            detects TLS from the handshake itself.
          </p>
          <div className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {FIXES.map((f) => (
              <div
                key={f.title}
                className="rounded-xl border border-term-line bg-term-panel/60 p-5 transition hover:border-cyan/30"
              >
                <div className="text-2xl">{f.icon}</div>
                <h3 className="mt-2 font-mono text-sm font-semibold text-slate-100">
                  {f.title}
                </h3>
                <p className="mt-2 font-mono text-[12px] leading-relaxed text-red-400/90">
                  <span className="text-slate-600">was · </span>
                  {f.bad}
                </p>
                <p className="mt-1 font-mono text-[12px] leading-relaxed text-green-400/90">
                  <span className="text-slate-600">now · </span>
                  {f.good}
                </p>
              </div>
            ))}
          </div>
        </section>

        {/* Quick start */}
        <section id="start" className="mt-16 scroll-mt-6">
          <h2 className="font-mono text-sm font-semibold uppercase tracking-widest text-cyan">
            ── Quick start · Termux
          </h2>
          <div className="mt-6 space-y-4">
            {STEPS.map((s, i) => (
              <div key={s.cmd}>
                <div className="mb-1 flex items-center gap-2 font-mono text-xs text-slate-500">
                  <span className="flex h-5 w-5 items-center justify-center rounded-full bg-cyan/15 text-cyan">
                    {i + 1}
                  </span>
                  {s.label}
                </div>
                <CodeBlock cmd={s.cmd} />
              </div>
            ))}
          </div>
        </section>

        {/* Examples */}
        <section className="mt-16">
          <h2 className="font-mono text-sm font-semibold uppercase tracking-widest text-cyan">
            ── Example commands
          </h2>
          <div className="mt-6 space-y-4">
            <CodeBlock cmd={'./farhad -cidr 104.16.0.0/20,172.64.0.0/20 -ports 443,2053 -bench'} />
            <CodeBlock cmd={'./farhad -url "trojan://pass@host:443?security=tls&sni=host.com"'} />
            <CodeBlock cmd={'./farhad -range 104.16.0.1-104.16.0.254 -threads 64 -min-score 55'} />
          </div>
        </section>

        {/* Flags */}
        <section className="mt-16">
          <h2 className="font-mono text-sm font-semibold uppercase tracking-widest text-cyan">
            ── Flags
          </h2>
          <div className="mt-6 overflow-x-auto rounded-xl border border-term-line">
            <table className="w-full min-w-[520px] border-collapse font-mono text-sm">
              <thead>
                <tr className="border-b border-term-line text-left text-slate-500">
                  <th className="px-4 py-2.5 font-medium">Flag</th>
                  <th className="px-4 py-2.5 font-medium">Default</th>
                  <th className="px-4 py-2.5 font-medium">Description</th>
                </tr>
              </thead>
              <tbody>
                {FLAGS.map((f) => (
                  <tr key={f[0]} className="border-b border-term-line/50">
                    <td className="px-4 py-2.5 text-cyan">{f[0]}</td>
                    <td className="px-4 py-2.5 text-yellow-400">{f[1]}</td>
                    <td className="px-4 py-2.5 text-slate-400">{f[2]}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* Architecture */}
        <section className="mt-16">
          <h2 className="font-mono text-sm font-semibold uppercase tracking-widest text-cyan">
            ── Architecture
          </h2>
          <pre className="mt-6 overflow-x-auto rounded-xl border border-term-line bg-black/50 p-5 font-mono text-[12px] leading-relaxed text-slate-300">
            {ARCH}
          </pre>
          <p className="mt-3 font-mono text-[12px] leading-relaxed text-slate-500">
            A two-phase concurrent pipeline with a top-K min-heap — closed ports
            are filtered cheaply in phase 1, so phase 2 only does the expensive
            TLS + HTTP work on promising targets. A checkpoint auto-saves every
            30s and Ctrl+C exits gracefully.
          </p>
        </section>
      </main>

      <footer className="border-t border-term-line">
        <div className="mx-auto max-w-5xl px-5 py-8">
          <p className="font-mono text-[11px] text-slate-600">
            Farhad · Cloudflare Edge Intelligence Engine · MIT License · built for
            Termux &amp; Linux
          </p>
        </div>
      </footer>
    </div>
  );
}
