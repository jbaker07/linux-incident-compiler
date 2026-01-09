# Linux Telemetry Enablement Guide

This document describes how to configure Linux telemetry sources for the EDR capture agent.

## Overview

The Linux Incident Compiler captures telemetry from multiple sources:
- **eBPF probes** - Kernel-level tracing (exec, network, file I/O)
- **auditd** - Linux Audit Framework events
- **journald/syslog** - System logs (auth, service events)
- **procfs** - Process snapshots

## Prerequisites

### Kernel Requirements

```bash
# Check kernel version (5.8+ required for CO-RE eBPF)
uname -r

# Check BPF support
ls /sys/kernel/btf/vmlinux  # BTF must exist for CO-RE
```

### Capabilities for eBPF

The capture agent needs elevated privileges:

```bash
# Option 1: Run as root
sudo ./capture_linux_rotating

# Option 2: Use capabilities (recommended for production)
sudo setcap cap_bpf,cap_perfmon,cap_sys_ptrace+eip ./target/release/capture_linux_rotating
./capture_linux_rotating
```

## Auditd Configuration

For systems using auditd, add these rules for comprehensive coverage:

```bash
# /etc/audit/rules.d/edr.rules

# Process execution (syscall tracing)
-a always,exit -F arch=b64 -S execve -k edr_exec
-a always,exit -F arch=b32 -S execve -k edr_exec

# File access in sensitive directories
-w /etc/passwd -p wa -k edr_identity
-w /etc/shadow -p wa -k edr_identity
-w /etc/sudoers -p wa -k edr_privilege

# Network socket operations (optional, high volume)
# -a always,exit -F arch=b64 -S connect -k edr_network
# -a always,exit -F arch=b64 -S accept -k edr_network

# Module loading
-a always,exit -F arch=b64 -S init_module -S finit_module -k edr_kernel

# Reload rules
sudo augenrules --load
sudo systemctl restart auditd
```

### Verify Auditd

```bash
# Check audit status
sudo auditctl -s

# Check rules are loaded
sudo auditctl -l | grep edr

# Test by running a command and checking logs
ausearch -k edr_exec -ts recent
```

## Journald Configuration

Ensure journald is configured to retain logs:

```bash
# /etc/systemd/journald.conf
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=2G
RuntimeMaxUse=500M
```

```bash
# Apply changes
sudo systemctl restart systemd-journald
```

### Verify Journald

```bash
# Check journal status
journalctl --disk-usage

# View auth logs (SSH, sudo)
journalctl -u sshd --since "1 hour ago"
journalctl _COMM=sudo --since "1 hour ago"
```

## eBPF Verification

```bash
# Check if BPF is available
cat /proc/config.gz | gunzip | grep CONFIG_BPF

# Should show:
# CONFIG_BPF=y
# CONFIG_BPF_SYSCALL=y
# CONFIG_BPF_JIT=y

# Verify BTF exists (required for CO-RE)
ls -la /sys/kernel/btf/vmlinux
```

## Telemetry Directory Structure

```
/var/lib/edr/
├── segments/           # Captured telemetry (JSONL files)
│   ├── 000001.jsonl
│   ├── 000002.jsonl
│   └── ...
├── index.json          # Segment index
├── workbench.db        # SQLite database (signals, explanations)
├── license.json        # Optional Pro license
└── install_id          # Installation fingerprint
```

### Permissions

```bash
# Create directory with correct permissions
sudo mkdir -p /var/lib/edr/segments
sudo chown -R edr:edr /var/lib/edr  # Or your service user
sudo chmod 750 /var/lib/edr
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `EDR_TELEMETRY_ROOT` | `/var/lib/edr` | Root directory for all telemetry |
| `EDR_PLAYBOOKS_DIR` | (auto-detected) | Override playbooks directory |
| `EDR_WORKFLOW_SEED` | `false` | Enable WorkflowSeed synthetic signals |

## Troubleshooting

### "Permission denied" for eBPF

```bash
# Check capabilities
getcap ./capture_linux_rotating

# Verify user can use BPF
cat /proc/sys/kernel/unprivileged_bpf_disabled
# 0 = unprivileged BPF allowed
# 1 = requires CAP_BPF (default on modern kernels)
# 2 = BPF disabled entirely
```

### No events captured

1. Verify capture agent is running: `ps aux | grep capture_linux`
2. Check telemetry directory: `ls -la $EDR_TELEMETRY_ROOT/segments/`
3. Verify index.json exists: `cat $EDR_TELEMETRY_ROOT/index.json`
4. Check capture agent logs for errors

### Auditd events not appearing

```bash
# Check audit log
tail -f /var/log/audit/audit.log

# Verify rules
sudo auditctl -l

# Check for rule errors
sudo auditctl -s | grep -i error
```

## Security Considerations

- **Audit trail**: The capture agent creates a complete audit trail. Ensure logs are protected.
- **Disk space**: Monitor `/var/lib/edr` for disk usage. Old segments can be rotated.
- **Network isolation**: The EDR does not require network access. All processing is local.
- **Privilege separation**: Use a dedicated service user for production deployments.

## See Also

- [README.md](../README.md) - Quick start guide
- [SHIP_CHECKLIST.md](SHIP_CHECKLIST.md) - Release checklist
- [LICENSING.md](LICENSING.md) - License tiers and activation
