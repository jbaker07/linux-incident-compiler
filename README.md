# Linux Incident Compiler

Local-first Endpoint Detection & Response (EDR) workbench for Linux. Captures, analyzes, and documents security incidents without cloud connectivity.

## Components

- **capture_linux_rotating** - Continuous event capture from eBPF/procfs with rotating segments
- **edr-locald** - Signal detection engine with playbooks and hypothesis correlation
- **edr-server** - Web UI and REST API server

## Quick Start

```bash
# Build release binaries
cargo build --release --workspace

# Start the server (requires telemetry data)
export EDR_TELEMETRY_ROOT=/var/lib/edr/telemetry
./target/release/edr-server

# Open http://127.0.0.1:3000
```

## Requirements

- Linux kernel 5.8+ (for eBPF CO-RE)
- Rust 1.75+
- Root/CAP_BPF for capture agent

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
