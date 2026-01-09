//! Host context for Linux sensors
//! Provides minimal shared metadata (hostname, boot_id, uid/gid, timestamp helpers)
//! Zero dependencies on telemetry/gnn/trust plumbing

use serde::{Deserialize, Serialize};
use std::fs;

/// Minimal context object passed to all sensors
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostCtx {
    pub hostname: String,
    pub boot_id: String,
    pub uid: u32,
    pub gid: u32,
    pub kernel_version: String,
}

/// Check if running as root (uid == 0)
pub fn is_root() -> bool {
    unsafe { libc::getuid() == 0 }
}

/// Check if eBPF is likely available on this kernel
pub fn ebpf_available() -> bool {
    // Check for bpf() syscall availability via kernel version and /sys/fs/bpf
    std::path::Path::new("/sys/fs/bpf").exists()
}

impl Default for HostCtx {
    fn default() -> Self {
        Self::new()
    }
}

impl HostCtx {
    /// Create a new HostCtx by reading system metadata
    pub fn new() -> Self {
        let hostname = hostname::get()
            .ok()
            .and_then(|h| h.to_str().map(|s| s.to_string()))
            .unwrap_or_else(|| "unknown".to_string());

        let boot_id = Self::read_boot_id().unwrap_or_else(|_| String::new());
        let kernel_version = Self::read_kernel_version().unwrap_or_else(|_| "unknown".to_string());

        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        HostCtx {
            hostname,
            boot_id,
            uid,
            gid,
            kernel_version,
        }
    }

    /// Current time in milliseconds since UNIX_EPOCH
    pub fn now_ms(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64
    }

    /// Current time in seconds since UNIX_EPOCH (timestamp)
    pub fn now_ts(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Read kernel boot_id from /proc/sys/kernel/random/boot_id
    fn read_boot_id() -> std::io::Result<String> {
        let content = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        Ok(content.trim().to_string())
    }

    /// Read kernel version from /proc/version or uname
    fn read_kernel_version() -> std::io::Result<String> {
        let content = fs::read_to_string("/proc/version")?;
        // Extract version string (e.g. "5.15.0-164-generic")
        if let Some(version) = content.split_whitespace().nth(2) {
            Ok(version.to_string())
        } else {
            Ok(content.trim().to_string())
        }
    }
}

/// Type alias for backwards compatibility
pub type HostInfo = HostCtx;

impl HostInfo {
    /// Alias for HostCtx::new()
    pub fn collect() -> Self {
        HostCtx::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_ctx_creation() {
        let ctx = HostCtx::new();
        assert!(!ctx.hostname.is_empty());
        assert!(ctx.now_ms() > 0);
        assert!(ctx.now_ts() > 0);
    }
}
