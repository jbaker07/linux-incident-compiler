//! eBPF buffer sizing and resource limit configuration
//! Ensures stable defaults with environment variable overrides

use anyhow::{anyhow, Result};
use std::env;

/// eBPF buffer configuration
#[derive(Debug, Clone)]
pub struct EbpfConfig {
    /// Ringbuf size in bytes (default: 16MB)
    pub ringbuf_bytes: usize,

    /// Perf event array page count (default: 256 pages)
    pub perf_page_count: usize,

    /// BPF memory lock limit (will attempt to set via setrlimit)
    pub memlock_bytes: u64,

    /// BPF object pinning root directory
    pub pin_root: String,
}

impl Default for EbpfConfig {
    fn default() -> Self {
        Self {
            ringbuf_bytes: 16 * 1024 * 1024,  // 16 MB
            perf_page_count: 256,             // 256 pages * 4KB = 1 MB
            memlock_bytes: 512 * 1024 * 1024, // 512 MB
            pin_root: "/sys/fs/bpf/edr".to_string(),
        }
    }
}

impl EbpfConfig {
    /// Load configuration from environment variables with defaults
    pub fn from_env() -> Self {
        let mut config = Self::default();

        // EDR_EBPF_RB_BYTES: ringbuf size
        if let Ok(val) = env::var("EDR_EBPF_RB_BYTES") {
            if let Ok(bytes) = val.parse::<usize>() {
                config.ringbuf_bytes = bytes;
            }
        }

        // EDR_EBPF_PERF_PAGES: perf page count
        if let Ok(val) = env::var("EDR_EBPF_PERF_PAGES") {
            if let Ok(pages) = val.parse::<usize>() {
                config.perf_page_count = pages;
            }
        }

        // EDR_EBPF_MEMLOCK_BYTES: memlock limit
        if let Ok(val) = env::var("EDR_EBPF_MEMLOCK_BYTES") {
            if let Ok(bytes) = val.parse::<u64>() {
                config.memlock_bytes = bytes;
            }
        }

        // EDR_BPF_PIN_ROOT: BPF pin directory
        if let Ok(val) = env::var("EDR_BPF_PIN_ROOT") {
            config.pin_root = val;
        }

        config
    }

    /// Attempt to raise RLIMIT_MEMLOCK for BPF usage (stub - would use libc/nix on actual deployment)
    pub fn setup_memlock(&self) -> Result<()> {
        // On actual Linux deployment, this would:
        // use resource::{getrlimit, setrlimit, Resource};
        // if soft < self.memlock_bytes { setrlimit(...) }
        // For now, stub implementation
        Ok(())
    }

    /// Validate configuration is reasonable
    pub fn validate(&self) -> Result<()> {
        if self.ringbuf_bytes < 256 * 1024 {
            return Err(anyhow!("ringbuf_bytes too small (min 256KB)"));
        }
        if self.ringbuf_bytes > 1024 * 1024 * 1024 {
            return Err(anyhow!("ringbuf_bytes too large (max 1GB)"));
        }

        if self.perf_page_count < 8 {
            return Err(anyhow!("perf_page_count too small (min 8)"));
        }
        if self.perf_page_count > 65536 {
            return Err(anyhow!("perf_page_count too large (max 65536)"));
        }

        Ok(())
    }

    /// Report configuration for heartbeat
    pub fn to_heartbeat_json(&self) -> serde_json::Value {
        serde_json::json!({
            "ebpf_ringbuf_size_bytes": self.ringbuf_bytes,
            "ebpf_perf_page_count": self.perf_page_count,
            "ebpf_memlock_bytes": self.memlock_bytes,
            "ebpf_pin_root": self.pin_root,
        })
    }
}
