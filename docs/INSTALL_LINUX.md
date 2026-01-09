# Linux Installation Guide

This guide covers installing and running the Linux Incident Compiler on supported distributions.

---

## Supported Distributions

| Distribution | Version | Architecture | Status |
|--------------|---------|--------------|--------|
| Ubuntu | 22.04 LTS | x86_64, arm64 | ✅ Full Support |
| Ubuntu | 24.04 LTS | x86_64, arm64 | ✅ Full Support |
| Debian | 12 (Bookworm) | x86_64, arm64 | ✅ Full Support |
| Rocky Linux | 9 | x86_64, arm64 | ✅ Full Support |
| Fedora | 39+ | x86_64, arm64 | ⚠️ Community |

---

## Quick Start

### Option 1: Tauri Desktop App (Recommended for Users)

```bash
# Download the release package for your distro
wget https://releases.example.com/edr-desktop-1.0.0.deb  # Ubuntu/Debian
# OR
wget https://releases.example.com/edr-desktop-1.0.0.rpm  # Rocky/RHEL

# Install
sudo dpkg -i edr-desktop-*.deb   # Ubuntu/Debian
# OR
sudo rpm -i edr-desktop-*.rpm    # Rocky/RHEL

# Run
edr-desktop
```

### Option 2: Systemd Service (Recommended for Servers)

```bash
# Clone or download release
git clone https://github.com/yourorg/linux-incident-compiler.git
cd linux-incident-compiler

# Build (requires Rust toolchain)
cargo build --release

# Install systemd services
sudo ./scripts/install_systemd.sh

# Start the stack
sudo systemctl start edr.target

# Verify
curl http://localhost:3000/api/health
```

---

## Package Requirements

### Base Requirements (All Distros)

| Package | Purpose |
|---------|---------|
| glibc 2.35+ | C runtime |
| OpenSSL 3.0+ | TLS/crypto |
| systemd | Service management |

### Tauri Desktop Requirements

| Distribution | Command |
|--------------|---------|
| **Ubuntu 22.04/24.04** | `sudo apt install -y libwebkit2gtk-4.1-0 libgtk-3-0 libayatana-appindicator3-1` |
| **Debian 12** | `sudo apt install -y libwebkit2gtk-4.1-0 libgtk-3-0` |
| **Rocky 9** | `sudo dnf install -y webkit2gtk4.1 gtk3` |

### Build Requirements (Development)

| Distribution | Command |
|--------------|---------|
| **Ubuntu 22.04/24.04** | `sudo apt install -y build-essential pkg-config libssl-dev libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev` |
| **Debian 12** | `sudo apt install -y build-essential pkg-config libssl-dev libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev` |
| **Rocky 9** | `sudo dnf install -y gcc gcc-c++ make openssl-devel webkit2gtk4.1-devel gtk3-devel librsvg2-devel` |

### Optional eBPF Requirements

For extended telemetry with eBPF capture (kernel 5.4+):

| Distribution | Command |
|--------------|---------|
| **Ubuntu 22.04/24.04** | `sudo apt install -y clang libelf-dev libbpf-dev linux-headers-$(uname -r)` |
| **Debian 12** | `sudo apt install -y clang libelf-dev libbpf-dev linux-headers-$(uname -r)` |
| **Rocky 9** | `sudo dnf install -y clang elfutils-libelf-devel libbpf-devel kernel-devel` |

---

## Installation Methods

### Method 1: Package Installation (Recommended)

#### Ubuntu / Debian (.deb)

```bash
# Download the latest release
wget https://releases.example.com/linux-incident-compiler_1.0.0_amd64.deb

# Install dependencies and package
sudo apt update
sudo apt install -y ./linux-incident-compiler_*.deb

# Verify installation
edr-server --version
```

#### Rocky Linux / RHEL (.rpm)

```bash
# Download the latest release
wget https://releases.example.com/linux-incident-compiler-1.0.0.x86_64.rpm

# Install
sudo dnf install -y ./linux-incident-compiler-*.rpm

# Verify installation
edr-server --version
```

### Method 2: Build from Source

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Clone the repository
git clone https://github.com/yourorg/linux-incident-compiler.git
cd linux-incident-compiler

# Install build dependencies (see table above)

# Build release binaries
cargo build --release

# Optionally build with eBPF support
cargo build --release -p agent-linux --features with-ebpf-load

# Install to system
sudo ./scripts/install_systemd.sh
```

---

## Running the Stack

### Desktop Mode (Tauri GUI)

The Tauri app provides a graphical interface to start/stop capture and view incidents.

```bash
# Run from build directory
./src-tauri/target/release/edr-desktop

# Or if installed via package
edr-desktop
```

**Features:**
- Start/Stop capture with one click
- View real-time telemetry status
- Analyze incidents with the workbench
- Export reports

### Headless Mode (Systemd)

For servers without a display, use systemd services.

```bash
# Install services
sudo ./scripts/install_systemd.sh

# Start the full stack
sudo systemctl start edr.target

# Check status
sudo systemctl status edr.target
sudo systemctl status edr-capture
sudo systemctl status edr-locald
sudo systemctl status edr-server

# View logs
sudo journalctl -u edr-server -f

# Stop the stack
sudo systemctl stop edr.target
```

### Manual Headless Mode (Without Systemd)

```bash
# Terminal 1: Start capture
sudo ./target/release/capture_linux_rotating \
  --output /var/lib/edr/telemetry/segments

# Terminal 2: Start local daemon
EDR_TELEMETRY_ROOT=/var/lib/edr/telemetry \
EDR_PLAYBOOKS_DIR=./playbooks/linux \
./target/release/edr-locald

# Terminal 3: Start server
EDR_TELEMETRY_ROOT=/var/lib/edr/telemetry \
./target/release/edr-server --port 3000
```

---

## Capture Modes

The capture service supports three modes with different privilege levels:

### Core Mode (No Root Required)

- Uses `/proc` filesystem monitoring
- File system events via inotify
- Network connections via netlink
- **Limitations:** No kernel-level visibility, no process arguments

```bash
# Run as regular user
./target/release/capture_linux_rotating --mode core
```

### Extended Mode (Root Required)

- Full audit log access
- Process execution with arguments
- File integrity monitoring
- **Requires:** Root or `CAP_DAC_READ_SEARCH`

```bash
# Run as root
sudo ./target/release/capture_linux_rotating --mode extended
```

### eBPF Mode (Kernel 5.4+, Root or Capabilities)

- Kernel-level syscall tracing
- Network flow capture
- Process provenance chains
- **Requires:** Root or `CAP_BPF + CAP_PERFMON + CAP_SYS_ADMIN`

```bash
# Run with capabilities (recommended)
sudo setcap cap_bpf,cap_perfmon,cap_sys_admin=ep ./capture_linux_rotating
./target/release/capture_linux_rotating --mode ebpf

# Or run as root
sudo ./target/release/capture_linux_rotating --mode ebpf
```

### Auto-Detection

The capture service auto-detects the best available mode:

```bash
# Auto-detect mode based on privileges and kernel
./target/release/capture_linux_rotating --mode auto
```

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `EDR_TELEMETRY_ROOT` | `/var/lib/edr/telemetry` (service) or `~/.local/share/linux-incident-compiler/telemetry` (user) | Base directory for telemetry |
| `EDR_PLAYBOOKS_DIR` | `/opt/edr/playbooks/linux` | Playbook YAML files |
| `EDR_PORT` | `3000` | HTTP API port |
| `RUST_LOG` | `info` | Log level (debug, info, warn, error) |

### Telemetry Directory Structure

```
/var/lib/edr/
├── telemetry/
│   ├── runs/
│   │   └── <run_id>/
│   │       ├── segments/     # Raw telemetry
│   │       ├── logs/         # Per-run logs
│   │       ├── metrics/      # GROUNDED metrics
│   │       └── incidents/    # Detected incidents
│   └── db/                   # SQLite databases
└── license/                  # License files
```

---

## Verifying Installation

### Health Check

```bash
# Check API health
curl -s http://localhost:3000/api/health | jq .

# Expected output:
# { "status": "ok", "version": "1.0.0" }
```

### License Status

```bash
# Check license status
curl -s http://localhost:3000/api/license/status | jq .

# Expected output:
# { "install_id": "...", "tier": "free", ... }
```

### Readiness Check

```bash
# Check capture readiness
curl -s http://localhost:3000/api/readiness | jq .

# Expected output shows available capture modes
```

### Playbooks

```bash
# List loaded playbooks
curl -s http://localhost:3000/api/playbooks | jq .
```

---

## Troubleshooting

### Common Issues

#### Permission Denied

```
Error: Permission denied opening /proc/*/...
```

**Solution:** Run capture as root or with capabilities:
```bash
sudo setcap cap_dac_read_search=ep ./capture_linux_rotating
```

#### WebKit2GTK Not Found

```
error while loading shared libraries: libwebkit2gtk-4.1.so.0
```

**Solution:** Install WebKit2GTK:
```bash
# Ubuntu/Debian
sudo apt install libwebkit2gtk-4.1-0

# Rocky/RHEL
sudo dnf install webkit2gtk4.1
```

#### eBPF Not Available

```
eBPF not available: kernel too old or missing CAP_BPF
```

**Solution:** 
1. Check kernel version: `uname -r` (needs 5.4+, 5.10+ recommended)
2. Install eBPF dependencies
3. Run with root or set capabilities

#### Port Already in Use

```
Error: Port 3000 already in use
```

**Solution:**
```bash
# Find and stop the process
sudo lsof -i :3000
sudo systemctl stop edr.target
```

### Checking Logs

```bash
# Systemd journal logs
sudo journalctl -u edr-server -n 100
sudo journalctl -u edr-capture -n 100
sudo journalctl -u edr-locald -n 100

# Follow logs in real-time
sudo journalctl -u edr-server -f
```

---

## Security Considerations

### Principle of Least Privilege

The systemd services are configured with security hardening:

- `NoNewPrivileges=yes` - Prevent privilege escalation
- `ProtectSystem=strict` - Read-only system directories
- `PrivateTmp=yes` - Isolated /tmp
- `ProtectHome=yes` - No access to home directories

### Capabilities vs Root

For eBPF capture, prefer capabilities mode over full root:

```bash
# Install with capabilities mode
sudo ./scripts/install_systemd.sh --caps
```

Required capabilities:
- `CAP_BPF` - Load eBPF programs
- `CAP_PERFMON` - Access perf events
- `CAP_SYS_ADMIN` - Kernel tracing (fallback)
- `CAP_DAC_READ_SEARCH` - Read files for provenance

### Network Access

The edr-server binds to localhost by default. For remote access:

```bash
# Bind to all interfaces (not recommended without firewall)
edr-server --bind 0.0.0.0 --port 3000
```

---

## Uninstallation

### Package Removal

```bash
# Ubuntu/Debian
sudo apt remove linux-incident-compiler

# Rocky/RHEL
sudo dnf remove linux-incident-compiler
```

### Systemd Removal

```bash
# Remove services (keep data)
sudo ./scripts/uninstall_systemd.sh

# Remove everything including data
sudo ./scripts/uninstall_systemd.sh --purge
```

---

## Support

- Documentation: `docs/`
- Smoke Tests: `docs/SMOKE_DISTROS.md`
- eBPF Guide: `docs/EBPF.md`
- Issue Tracker: GitHub Issues
