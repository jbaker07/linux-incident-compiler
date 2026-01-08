# Ship Checklist for Linux Incident Compiler

This document is a pre-release security and quality audit checklist.
All items must pass before tagging a release.

## 🔐 Security Audit

### Private Key Material
- [x] **PASS**: `SigningKey` only appears in `license_gen.rs` (vendor-only tool)
- [x] **PASS**: No hardcoded private keys found in codebase
- [x] **PASS**: CI scans shipping binaries for forbidden patterns:
  - `SigningKey`
  - `PRIVATE_KEY`
  - `EDR_LICENSE_PRIVATE_KEY`
  - `-----BEGIN PRIVATE KEY-----`
  - `ed25519_secret`

### Forbidden Binaries
- [x] **PASS**: `license_gen` in forbidden_binaries list (`packaging/allowlist.json`)
- [x] **PASS**: `golden-cli` in forbidden_binaries list
- [x] **PASS**: Other internal/dev tools excluded:
  - `proof_run`
  - `metrics_run`
  - `explain_harness`
  - `agent-linux` (library artifact)

### Fingerprint Privacy
- [x] **PASS**: Fingerprint is SHA256 hash, not raw machine data
- [x] **PASS**: Only 16 hex chars (64 bits) stored - not reversible
- [x] **PASS**: Linux components: `/etc/machine-id` + CPU model + OS version (no PII)
- [x] **PASS**: Documentation states "not personally identifiable"

### License Security
- [x] **PASS**: Ed25519 signature verification with public key only
- [x] **PASS**: Key rotation support via `LICENSE_PUBLIC_KEYS_ROTATED`
- [x] **PASS**: Machine binding prevents simple license copying
- [x] **PASS**: Clock tamper detection implemented

## 📦 Packaging Audit

### Artifact Validation
- [x] **PASS**: Single source of truth: `packaging/allowlist.json`
- [x] **PASS**: CI validates artifacts against allowlist
- [x] **PASS**: Release workflow validates artifacts against allowlist
- [x] **PASS**: JSON schema provided for allowlist validation

### Required Linux Binaries
- [x] `edr-server` - Web UI and API server
- [x] `edr-locald` - Local daemon for event processing  
- [x] `capture_linux_rotating` - Linux eBPF/auditd capture agent

### Required Assets
- [x] `ui/` directory with all frontend files
- [x] `README.md` documentation
- [x] `MANIFEST.txt` with SHA256 checksums

### Linux-Specific Requirements
- [x] Kernel 5.8+ for eBPF CO-RE support
- [x] CAP_BPF/CAP_SYS_ADMIN for capture agent
- [x] `/var/lib/edr/` data directory permissions

## 🎨 UX Audit

### License Panel
- [x] **PASS**: Installation ID always visible with copy button
- [x] **PASS**: Machine binding status displayed
- [x] **PASS**: Clear status icons for all license states:
  - ✅ Valid
  - 🔒 Not Installed
  - ⏰ Expired
  - ❌ Invalid
  - 🔄 Wrong Installation
  - ⚙️ Not Configured (dev)

### Error States
- [x] **PASS**: 402 responses show clear "Pro License Required" banner
- [x] **PASS**: 403 responses show "Machine Binding Error" with support guidance
- [x] **PASS**: Installation ID shown in error banners for easy support contact

### Watermarking
- [x] **PASS**: Diff reports include license watermark
- [x] **PASS**: Bundle exports include watermark metadata

## 🧪 Quality Gates

### Pre-Release Verification (Linux)
```bash
# All must pass before tagging
cargo fmt -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --release

# Linux-specific integration tests
cargo test --package edr-locald --test golden_linux_integration
```

### Build Verification (Linux)
```bash
# Verify release build produces correct binaries
cargo build --release --bin edr-server --bin edr-locald -p agent-linux

# Verify binaries exist
ls -la target/release/edr-server target/release/edr-locald target/release/capture_linux_rotating
```

### Linux Telemetry Validation
```bash
# Verify capture agent can attach eBPF probes (requires root/CAP_BPF)
sudo ./target/release/capture_linux_rotating --dry-run

# Verify fact extraction pipeline
cargo test --package edr-locald -- --test-threads=1 linux
```

## ✅ Final Sign-Off

| Check | Status | Date | Notes |
|-------|--------|------|-------|
| Security Audit | ✅ PASS | | No private key material in shipping binaries |
| Packaging Audit | ✅ PASS | | Allowlist validation in place |
| UX Audit | ✅ PASS | | License panel complete |
| Linux Fact Extraction | ✅ PASS | | fact_extractor.rs implemented |
| Linux Signal Engine | ✅ PASS | | signal_engine.rs functional |
| Golden Integration Test | ✅ PASS | | golden_linux_integration.rs passes |
| Quality Gates | ⏳ PENDING | | Run before final tag |
| Tag v0.1.0-linux | ⏳ PENDING | | After quality gates pass |

---

## Changelog Summary for v0.1.0-linux

### Added
- Linux fact extractor (`os/linux/fact_extractor.rs`) - converts auditd/eBPF/journald events to canonical facts
- Tag enrichment for Linux telemetry sources (auditd syscalls, journald units, eBPF probes)
- Golden Linux integration test (`golden_linux_integration.rs`)
- Linux-specific detection coverage:
  - Suspicious path execution (/tmp, /dev/shm, /var/tmp)
  - Reverse shell detection
  - Privilege escalation (uid/euid mismatch)
  - Kernel module loading
  - Critical file modification
  - SSH key injection
  - Container escape precursors

### Linux Playbook Coverage
- 31 Linux playbooks in `playbooks/linux/`
- Key TTPs covered: T1059 (Command Execution), T1105 (Ingress Transfer), T1505.003 (Webshell), T1611 (Container Escape)

### Platform Parity
- Machine fingerprint: `/etc/machine-id` + CPU + OS version
- Data directory: `/var/lib/edr/` (root) or `~/.local/share/edr/` (non-root)
- Install ID: UUID v4 persisted to `install_id` file
