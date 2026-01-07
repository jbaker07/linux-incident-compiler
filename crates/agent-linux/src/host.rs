//! Host context for Linux sensors
//! Provides minimal shared metadata (hostname, boot_id, uid/gid, timestamp helpers)
//! Zero dependencies on telemetry/gnn/trust plumbing

use std::fs;

/// Minimal context object passed to all sensors
#[derive(Clone, Debug)]
pub struct HostCtx {
    pub hostname: String,
    pub boot_id: String,
    pub uid: u32,
    pub gid: u32,
}

impl HostCtx {
    /// Create a new HostCtx by reading system metadata
    pub fn new() -> Self {
        let hostname = hostname::get()
            .ok()
            .and_then(|h| h.to_str().map(|s| s.to_string()))
            .unwrap_or_else(|| "unknown".to_string());

        let boot_id = Self::read_boot_id().unwrap_or_else(|_| String::new());

        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        HostCtx {
            hostname,
            boot_id,
            uid,
            gid,
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
