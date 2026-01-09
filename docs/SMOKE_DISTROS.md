# Multi-Distro Smoke Test Checklist

This document provides smoke test procedures for verifying Linux Incident Compiler functionality across supported distributions.

---

## Quick Reference

| Distro | Kernel | glibc | OpenSSL | systemd | WebKit2GTK |
|--------|--------|-------|---------|---------|------------|
| Ubuntu 22.04 | 5.15+ | 2.35 | 3.0.x | 249+ | 4.1 |
| Ubuntu 24.04 | 6.5+ | 2.39 | 3.0.x | 255+ | 4.1 |
| Debian 12 | 6.1 | 2.36 | 3.0.x | 252 | 4.1 |
| Rocky 9 | 5.14 | 2.34 | 3.0.x | 252 | 4.1 |

---

## Pre-Smoke Setup

### 1. Verify System Requirements

```bash
#!/bin/bash
# Save as: check_requirements.sh

echo "═══════════════════════════════════════════════════════════════"
echo "Linux Incident Compiler - System Requirements Check"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Detect distro
if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo "Distribution: $NAME $VERSION"
else
    echo "Distribution: Unknown"
fi

echo "Kernel: $(uname -r)"
echo "Architecture: $(uname -m)"
echo ""

# Check glibc
echo "glibc: $(ldd --version | head -1 | awk '{print $NF}')"

# Check OpenSSL
echo "OpenSSL: $(openssl version 2>/dev/null || echo 'Not found')"

# Check systemd
echo "systemd: $(systemctl --version | head -1 | awk '{print $2}')"

# Check kernel capabilities
echo ""
echo "=== Kernel Capabilities ==="
echo "eBPF support: $([ -d /sys/fs/bpf ] && echo 'Yes' || echo 'No')"
echo "Kernel version >= 5.4: $([ "$(uname -r | cut -d. -f1)" -ge 5 ] && echo 'Yes' || echo 'No')"

# Check for GUI support
echo ""
echo "=== GUI Support ==="
if command -v pkg-config &>/dev/null; then
    pkg-config --exists webkit2gtk-4.1 && echo "WebKit2GTK 4.1: Yes" || echo "WebKit2GTK 4.1: No"
    pkg-config --exists gtk+-3.0 && echo "GTK3: Yes" || echo "GTK3: No"
else
    echo "pkg-config not found - cannot check GUI libraries"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
```

---

## Smoke Test Procedures

### Phase 1: Binary Execution

#### Test 1.1: Server Binary

```bash
# Test binary exists and runs
./target/release/edr-server --help || echo "FAIL: Server help"
./target/release/edr-server --version 2>/dev/null || echo "Note: --version not implemented"

# Test library linkage
ldd ./target/release/edr-server | grep "not found" && echo "FAIL: Missing libraries" || echo "PASS: Libraries linked"
```

**Expected:** Binary executes without missing library errors.

#### Test 1.2: Capture Binary

```bash
# Test binary exists
ls -la ./target/release/capture_linux_rotating

# Test library linkage
ldd ./target/release/capture_linux_rotating | grep "not found" && echo "FAIL" || echo "PASS"

# Test execution (will fail without root, but should print usage)
./target/release/capture_linux_rotating --help 2>&1 || true
```

**Expected:** Binary exists and shows help/usage when run.

#### Test 1.3: Local Daemon Binary

```bash
./target/release/edr-locald --help || echo "FAIL: Locald help"
ldd ./target/release/edr-locald | grep "not found" && echo "FAIL" || echo "PASS"
```

### Phase 2: Service Installation

#### Test 2.1: Systemd Unit Installation

```bash
# Install systemd services
sudo ./scripts/install_systemd.sh

# Verify units are installed
systemctl list-unit-files | grep edr

# Expected output:
# edr-capture.service          disabled disabled
# edr-capture-caps.service     disabled disabled
# edr-locald.service           disabled disabled
# edr-server.service           disabled disabled
# edr.target                   disabled disabled
```

**Expected:** All 5 unit files installed.

#### Test 2.2: Service Start

```bash
# Start the stack
sudo systemctl start edr.target

# Check status
sudo systemctl status edr.target --no-pager
sudo systemctl status edr-server --no-pager
sudo systemctl status edr-capture --no-pager
sudo systemctl status edr-locald --no-pager
```

**Expected:** All services running (active).

#### Test 2.3: Service Logs

```bash
# Check for startup errors
sudo journalctl -u edr-server -n 20 --no-pager
sudo journalctl -u edr-capture -n 20 --no-pager
sudo journalctl -u edr-locald -n 20 --no-pager
```

**Expected:** No ERROR level logs, services initialized.

### Phase 3: API Health Check

#### Test 3.1: Health Endpoint

```bash
# Wait for server to start
sleep 2

# Check health
curl -s http://localhost:3000/api/health | jq .

# Expected output:
# { "status": "ok", ... }
```

#### Test 3.2: License Status

```bash
curl -s http://localhost:3000/api/license/status | jq .
```

**Expected:** Returns license info (install_id, tier).

#### Test 3.3: Playbooks Endpoint

```bash
curl -s http://localhost:3000/api/playbooks | jq .
```

**Expected:** Returns array of available playbooks.

### Phase 4: Capture Validation

#### Test 4.1: Telemetry Generation

```bash
# Check if telemetry is being written
ls -la /var/lib/edr/telemetry/

# Count events (after 30 seconds of capture)
sleep 30
find /var/lib/edr/telemetry/segments -name "*.gz" 2>/dev/null | wc -l
```

**Expected:** Segment files being created.

#### Test 4.2: Capture Mode Detection

```bash
# Check capture logs for mode
sudo journalctl -u edr-capture -n 50 | grep -i "mode\|ebpf\|core\|extended"
```

**Expected:** Logs show detected capture mode (core/extended/ebpf).

### Phase 5: Cleanup

#### Test 5.1: Service Stop

```bash
sudo systemctl stop edr.target
sudo systemctl status edr.target --no-pager
```

**Expected:** All services stopped.

#### Test 5.2: Uninstall

```bash
sudo ./scripts/uninstall_systemd.sh

# Verify removal
systemctl list-unit-files | grep edr
```

**Expected:** No edr units found.

---

## Distro-Specific Notes

### Ubuntu 22.04 LTS

```bash
# Install dependencies
sudo apt update
sudo apt install -y libwebkit2gtk-4.1-0 libgtk-3-0 libayatana-appindicator3-1

# Build dependencies (if building from source)
sudo apt install -y build-essential pkg-config libssl-dev \
    libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev \
    clang libelf-dev libbpf-dev
```

**Known Issues:**
- None

### Ubuntu 24.04 LTS

```bash
# Same as 22.04
sudo apt update
sudo apt install -y libwebkit2gtk-4.1-0 libgtk-3-0 libayatana-appindicator3-1
```

**Known Issues:**
- None

### Debian 12 (Bookworm)

```bash
# Install dependencies
sudo apt update
sudo apt install -y libwebkit2gtk-4.1-0 libgtk-3-0

# Note: libayatana-appindicator3 may not be available
# App indicator tray icon may not work
```

**Known Issues:**
- App indicator support varies by desktop environment
- Use GNOME or KDE for best compatibility

### Rocky Linux 9

```bash
# Enable CRB (CodeReady Builder) for development packages
sudo dnf config-manager --set-enabled crb
sudo dnf install -y epel-release

# Install runtime dependencies
sudo dnf install -y webkit2gtk4.1 gtk3

# Build dependencies
sudo dnf install -y gcc gcc-c++ make openssl-devel pkgconf-pkg-config \
    webkit2gtk4.1-devel gtk3-devel librsvg2-devel \
    clang elfutils-libelf-devel libbpf-devel
```

**Known Issues:**
- Kernel 5.14 has limited eBPF support compared to 5.15+
- Some eBPF features may require kernel upgrade

---

## Automated Smoke Test Script

```bash
#!/bin/bash
# smoke_test.sh - Automated smoke test for Linux Incident Compiler
set -e

PASS=0
FAIL=0

test_result() {
    if [ $1 -eq 0 ]; then
        echo "  ✓ PASS: $2"
        ((PASS++))
    else
        echo "  ✗ FAIL: $2"
        ((FAIL++))
    fi
}

echo "═══════════════════════════════════════════════════════════════"
echo "Linux Incident Compiler - Smoke Test"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Phase 1: Binary checks
echo "Phase 1: Binary Execution"
./target/release/edr-server --help &>/dev/null
test_result $? "edr-server executes"

./target/release/edr-locald --help &>/dev/null
test_result $? "edr-locald executes"

[ -f ./target/release/capture_linux_rotating ]
test_result $? "capture_linux_rotating exists"

# Phase 2: Linkage
echo ""
echo "Phase 2: Library Linkage"
! ldd ./target/release/edr-server 2>&1 | grep -q "not found"
test_result $? "edr-server libraries"

! ldd ./target/release/edr-locald 2>&1 | grep -q "not found"
test_result $? "edr-locald libraries"

# Phase 3: Start services (if sudo available)
echo ""
echo "Phase 3: Service Start"
if sudo -n true 2>/dev/null; then
    sudo ./scripts/install_systemd.sh &>/dev/null
    test_result $? "systemd install"
    
    sudo systemctl start edr.target
    sleep 2
    
    systemctl is-active edr-server.service &>/dev/null
    test_result $? "edr-server running"
    
    # Phase 4: API check
    echo ""
    echo "Phase 4: API Health"
    curl -sf http://localhost:3000/api/health &>/dev/null
    test_result $? "health endpoint"
    
    # Cleanup
    sudo systemctl stop edr.target
    sudo ./scripts/uninstall_systemd.sh &>/dev/null
else
    echo "  (Skipped - requires sudo)"
fi

# Summary
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Results: $PASS passed, $FAIL failed"
if [ $FAIL -eq 0 ]; then
    echo "Status: ALL TESTS PASSED ✓"
    exit 0
else
    echo "Status: SOME TESTS FAILED ✗"
    exit 1
fi
```

---

## CI Matrix Verification

The CI workflow tests across all supported distros:

| Job | Container | Tests |
|-----|-----------|-------|
| build-and-test (ubuntu-22.04) | `ubuntu:22.04` | Build, clippy, tests, smoke |
| build-and-test (ubuntu-24.04) | `ubuntu:24.04` | Build, clippy, tests, smoke |
| build-and-test (debian-12) | `debian:12` | Build, clippy, tests, smoke |
| build-and-test (rocky-9) | `rockylinux:9` | Build, clippy, tests, smoke |
| build-tauri | `ubuntu-22.04` (runner) | Tauri desktop build |

Each job verifies:
1. Dependencies install correctly
2. Rust toolchain works
3. All crates compile
4. All tests pass
5. Binaries link correctly
6. Basic execution works

---

## Troubleshooting

### Common Issues

#### "libssl.so.3: cannot open shared object file"

**Cause:** OpenSSL 3.x not installed.

**Ubuntu/Debian:**
```bash
sudo apt install libssl3
```

**Rocky:**
```bash
sudo dnf install openssl-libs
```

#### "libwebkit2gtk-4.1.so.0: cannot open shared object file"

**Cause:** WebKit2GTK not installed (only needed for Tauri desktop).

**Ubuntu/Debian:**
```bash
sudo apt install libwebkit2gtk-4.1-0
```

**Rocky:**
```bash
sudo dnf install webkit2gtk4.1
```

#### "Permission denied" when starting capture

**Cause:** Capture requires root or capabilities.

**Solution:**
```bash
# Option 1: Run as root (not recommended for production)
sudo systemctl start edr-capture

# Option 2: Use capabilities mode (recommended)
sudo setcap cap_bpf,cap_perfmon,cap_sys_admin,cap_dac_read_search=ep \
    /opt/edr/bin/capture_linux_rotating
sudo systemctl start edr-capture-caps
```

#### "SELinux preventing..." (Rocky/RHEL)

**Cause:** SELinux blocking service operations.

**Solution:**
```bash
# Check SELinux denials
sudo ausearch -m AVC -ts recent

# Create policy module (or set permissive temporarily)
sudo semanage permissive -a edr_t  # If custom policy exists

# Or set SELinux to permissive mode (not recommended for production)
sudo setenforce 0
```

---

## Sign-Off Checklist

Before release, verify each distro passes:

- [ ] **Ubuntu 22.04**: All Phase 1-5 tests pass
- [ ] **Ubuntu 24.04**: All Phase 1-5 tests pass
- [ ] **Debian 12**: All Phase 1-5 tests pass
- [ ] **Rocky 9**: All Phase 1-5 tests pass
- [ ] **Tauri Desktop**: Launches on reference platform (Ubuntu 22.04)
- [ ] **Package Install**: .deb installs on Ubuntu/Debian
- [ ] **Package Install**: .rpm installs on Rocky
