# Linux Incident Compiler

Local-first Endpoint Detection & Response (EDR) workbench for Linux. Captures, analyzes, and documents security incidents without cloud connectivity.

## Components

- **capture_linux_rotating** - Continuous event capture from eBPF/procfs with rotating segments
- **edr-locald** - Signal detection engine with playbooks and hypothesis correlation
- **edr-server** - Web UI and REST API server

## Quick Start (Linux)

```bash
# 1. Build release binaries
cargo build --release --workspace

# 2. Set up telemetry directory (requires root for /var/lib)
export EDR_TELEMETRY_ROOT=/var/lib/edr
sudo mkdir -p $EDR_TELEMETRY_ROOT/segments
sudo chown $USER:$USER $EDR_TELEMETRY_ROOT

# 3. Start all three processes (each in its own terminal or use &)

# Terminal 1: Start capture agent (requires root/CAP_BPF for eBPF)
sudo -E ./target/release/capture_linux_rotating

# Terminal 2: Start signal detection daemon
./target/release/edr-locald

# Terminal 3: Start web server
./target/release/edr-server

# 4. Open the web UI
# http://127.0.0.1:3000

# 5. Verify signals are being detected
curl http://localhost:3000/api/signals | jq '.data | length'
```

### Development Mode (non-root testing)

```bash
# Use /tmp for telemetry (no root required)
export EDR_TELEMETRY_ROOT=/tmp/edr-test
mkdir -p $EDR_TELEMETRY_ROOT/segments

# Skip capture agent, run locald + server with test data
./target/release/edr-locald &
./target/release/edr-server &

# Seed test telemetry (optional)
# cp testdata/segments/*.jsonl $EDR_TELEMETRY_ROOT/segments/
```

## Requirements

- Linux kernel 5.8+ (for eBPF CO-RE)
- Rust 1.75+
- Root/CAP_BPF for capture agent

See [docs/TELEMETRY_ENABLEMENT_LINUX.md](docs/TELEMETRY_ENABLEMENT_LINUX.md) for detailed telemetry setup.

## Licensing

This software uses a runtime-gated licensing model:
- **Free tier**: Full capture, timeline, signal detection
- **Pro tier**: Diff mode, pro reports, team features

See [docs/LICENSING.md](docs/LICENSING.md) for details.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Linux Machine                              │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐   ┌─────────────────┐   ┌───────────────┐  │
│  │capture_linux    │   │   edr-locald    │   │  edr-server   │  │
│  │  _rotating      │──▶│                 │──▶│               │  │
│  │                 │   │ • Playbooks     │   │ • Web UI      │  │
│  │ • eBPF probes   │   │ • Hypothesis    │   │ • REST API    │  │
│  │ • procfs        │   │ • Scoring       │   │ • Reports     │  │
│  │ • auditd        │   │ • Baselines     │   │ • License     │  │
│  └─────────────────┘   └─────────────────┘   └───────────────┘  │
│           │                    │                    │            │
│           ▼                    ▼                    ▼            │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │              /var/lib/edr/                                  ││
│  │  • telemetry/runs/         (captured events)                ││
│  │  • signals.db              (detected signals)               ││
│  │  • workbench.db            (incident docs)                  ││
│  │  • license.json            (Pro license)                    ││
│  │  • install_id              (unique installation)            ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

## License

MIT
