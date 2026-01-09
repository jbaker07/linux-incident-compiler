# eBPF Capture Build Guide

This document explains how to build the **optional** eBPF-based capture system for
high-fidelity kernel-level telemetry on Linux.

> **Note:** eBPF is **completely optional**. The default build works without any eBPF
> dependencies. Only enable this feature if you need kernel-level process, network,
> and file monitoring.

---

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Building the eBPF Capture Binary](#building-the-ebpf-capture-binary)
- [Runtime Requirements](#runtime-requirements)
- [Troubleshooting](#troubleshooting)
- [CI Integration](#ci-integration)

---

## Overview

The eBPF capture system uses kernel probes to collect:

| Capability | eBPF Program | Description |
|------------|--------------|-------------|
| Process Events | `exec_provenance.bpf.c` | Process execution with full argv/envp |
| Network Flows | `net_flow.bpf.c` | TCP/UDP connection tracking |
| File Operations | `file_ops.bpf.c` | File open/read/write/unlink events |
| DNS Queries | `dns_query.bpf.c` | DNS request/response capture |
| Module Loads | `module_load.bpf.c` | Kernel module loading events |

### Feature Flags

| Feature | Description |
|---------|-------------|
| `with-ebpf` | Enables eBPF crate dependencies (libbpf-rs, aya) |
| `with-ebpf-load` | Full eBPF loader + capture binary (includes `with-ebpf`) |

---

## Prerequisites

### System Requirements

- **Linux Kernel:** 5.4+ (5.10+ recommended for BTF support)
- **Architecture:** x86_64 or aarch64 (ARM64)
- **Distribution:** Ubuntu 20.04+, Debian 11+, Fedora 34+, Arch Linux

### Build Dependencies

Run the preflight check to verify your system:

```bash
./scripts/ebpf-preflight.sh
```

#### Ubuntu / Debian

```bash
sudo apt update
sudo apt install -y clang libelf-dev libbpf-dev zlib1g-dev make pkg-config \
    linux-headers-$(uname -r)
```

#### Fedora

```bash
sudo dnf install -y clang elfutils-libelf-devel libbpf-devel zlib-devel make \
    pkgconf kernel-devel
```

#### Arch Linux

```bash
sudo pacman -S clang libelf libbpf zlib make pkgconf linux-headers
```

---

## Quick Start

```bash
# 1. Verify prerequisites
./scripts/ebpf-preflight.sh

# 2. Build the eBPF capture binary
cargo build -p agent-linux --features with-ebpf-load --release

# 3. Run with elevated privileges (required for BPF syscalls)
sudo ./target/release/capture_linux_rotating --help
```

---

## Building the eBPF Capture Binary

### Development Build

```bash
cargo build -p agent-linux --features with-ebpf-load
```

### Release Build

```bash
cargo build -p agent-linux --features with-ebpf-load --release
```

### Build Output

The build produces the `capture_linux_rotating` binary in `target/{debug,release}/`.

### Compiling BPF Programs Manually (Optional)

The BPF C programs are compiled automatically via `build.rs`. To manually rebuild:

```bash
cd crates/agent-linux/src/ebpf
make clean && make
```

This produces `.bpf.o` object files from the `.bpf.c` sources.

---

## Runtime Requirements

### Privileges

eBPF requires elevated privileges. Options:

1. **Run as root** (simplest):
   ```bash
   sudo ./capture_linux_rotating
   ```

2. **Use CAP_BPF + CAP_PERFMON** (recommended for production):
   ```bash
   sudo setcap cap_bpf,cap_perfmon=ep ./capture_linux_rotating
   ./capture_linux_rotating
   ```

3. **Unprivileged BPF** (kernel 5.8+, requires sysctl):
   ```bash
   sudo sysctl kernel.unprivileged_bpf_disabled=0
   ```

### Kernel Configuration

Most modern distributions have the required kernel options enabled. Verify with:

```bash
# Check BPF support
zcat /proc/config.gz 2>/dev/null | grep -E "CONFIG_BPF|CONFIG_KPROBE" || \
  grep -E "CONFIG_BPF|CONFIG_KPROBE" /boot/config-$(uname -r)
```

Required options:
- `CONFIG_BPF=y`
- `CONFIG_BPF_SYSCALL=y`
- `CONFIG_KPROBES=y`
- `CONFIG_TRACEPOINTS=y`

---

## Troubleshooting

### Build Errors

| Error | Solution |
|-------|----------|
| `bpf/libbpf.h: No such file` | Install `libbpf-dev` (Ubuntu) or `libbpf-devel` (Fedora) |
| `libelf.h: No such file` | Install `libelf-dev` (Ubuntu) or `elfutils-libelf-devel` (Fedora) |
| `clang: command not found` | Install `clang` package |
| `linux/bpf.h: No such file` | Install kernel headers: `linux-headers-$(uname -r)` |

### Runtime Errors

| Error | Solution |
|-------|----------|
| `EPERM: Operation not permitted` | Run with `sudo` or add CAP_BPF capability |
| `EINVAL: Invalid argument` | Kernel version too old; need 5.4+ |
| `libbpf: failed to load program` | Check `dmesg` for verifier errors |

### Debug Mode

Enable verbose BPF loading logs:

```bash
RUST_LOG=debug sudo ./capture_linux_rotating
```

---

## CI Integration

The eBPF build is **optional** in CI. To enable it, set the `ENABLE_EBPF_BUILD`
environment variable:

```yaml
# GitHub Actions example
jobs:
  build-ebpf:
    runs-on: ubuntu-latest
    env:
      ENABLE_EBPF_BUILD: "1"
    steps:
      - uses: actions/checkout@v4
      
      - name: Install eBPF dependencies
        run: |
          sudo apt update
          sudo apt install -y clang libelf-dev libbpf-dev linux-headers-$(uname -r)
      
      - name: Build with eBPF
        run: cargo build -p agent-linux --features with-ebpf-load
```

### CI Guard Pattern

```yaml
- name: Build (with optional eBPF)
  run: |
    if [ "$ENABLE_EBPF_BUILD" = "1" ]; then
      cargo build -p agent-linux --features with-ebpf-load
    else
      cargo build -p agent-linux
    fi
```

---

## Architecture Notes

### Supported Architectures

| Arch | TARGET_ARCH | Notes |
|------|-------------|-------|
| x86_64 | `x86` | Full support |
| aarch64 | `arm64` | Full support |
| armv7 | — | Not supported (32-bit) |

### BPF CO-RE (Compile Once, Run Everywhere)

The BPF programs use CO-RE for kernel compatibility. This requires:

- **BTF (BPF Type Format)** in the kernel (`CONFIG_DEBUG_INFO_BTF=y`)
- Most kernels 5.10+ have this enabled by default

Check BTF availability:

```bash
ls -la /sys/kernel/btf/vmlinux
```

---

## Security Considerations

- eBPF programs run in kernel context with access to sensitive data
- The capture binary should be deployed with minimal necessary privileges
- Consider running in a dedicated security context (SELinux/AppArmor)
- BPF programs are verified by the kernel but still represent increased attack surface

---

## Further Reading

- [Linux BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/)
- [libbpf-rs Crate](https://docs.rs/libbpf-rs/)
- [Aya (Rust eBPF)](https://aya-rs.dev/)
