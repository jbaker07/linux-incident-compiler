//! UID State Cache for Before/After Tracking
//!
//! Maintains per-PID UID/capability state to compute before/after values
//! when privilege escalation events (EVT_SETUID, EVT_CAPSET) are received.
//!
//! The eBPF layer only gives us the current state; we need to track the
//! previous state to emit proper PrivilegeBoundary facts.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Process credential state
#[derive(Debug, Clone)]
pub struct ProcCredState {
    pub pid: u32,
    pub uid: u32,
    pub euid: u32,
    pub gid: u32,
    pub egid: u32,
    /// Capability bitmask (effective)
    pub caps_effective: u64,
    /// Last update time for LRU eviction
    last_seen: Instant,
}

impl Default for ProcCredState {
    fn default() -> Self {
        Self {
            pid: 0,
            uid: 65534, // nobody
            euid: 65534,
            gid: 65534,
            egid: 65534,
            caps_effective: 0,
            last_seen: Instant::now(),
        }
    }
}

/// Credential change result
#[derive(Debug, Clone)]
pub struct CredChange {
    pub uid_before: u32,
    pub uid_after: u32,
    pub euid_before: u32,
    pub euid_after: u32,
    pub caps_added: Vec<String>,
    pub caps_removed: Vec<String>,
}

/// UID state cache with LRU eviction
pub struct UidCache {
    cache: RwLock<HashMap<u32, ProcCredState>>,
    max_entries: usize,
    ttl: Duration,
}

impl Default for UidCache {
    fn default() -> Self {
        Self::new(50_000, Duration::from_secs(3600))
    }
}

impl UidCache {
    /// Create a new UID cache
    pub fn new(max_entries: usize, ttl: Duration) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            max_entries,
            ttl,
        }
    }

    /// Update credentials and return the change
    pub fn update(
        &self,
        pid: u32,
        uid: u32,
        euid: u32,
        gid: u32,
        egid: u32,
        caps: u64,
    ) -> CredChange {
        let mut cache = self.cache.write().unwrap();

        // Evict if at capacity
        if cache.len() >= self.max_entries {
            self.evict_expired(&mut cache);
        }

        let now = Instant::now();

        let old_state = cache.get(&pid).cloned().unwrap_or(ProcCredState {
            // First time seeing this PID - assume inherited from parent or default
            pid,
            uid,
            euid: uid, // Assume started with same real/effective
            gid,
            egid: gid,
            caps_effective: 0,
            last_seen: now,
        });

        // Compute capability changes
        let caps_added = Self::caps_diff(caps, old_state.caps_effective);
        let caps_removed = Self::caps_diff(old_state.caps_effective, caps);

        let change = CredChange {
            uid_before: old_state.uid,
            uid_after: uid,
            euid_before: old_state.euid,
            euid_after: euid,
            caps_added,
            caps_removed,
        };

        // Update state
        cache.insert(
            pid,
            ProcCredState {
                pid,
                uid,
                euid,
                gid,
                egid,
                caps_effective: caps,
                last_seen: now,
            },
        );

        change
    }

    /// Get current state without updating
    pub fn get(&self, pid: u32) -> Option<ProcCredState> {
        self.cache.read().unwrap().get(&pid).cloned()
    }

    /// Record process exit (remove from cache)
    pub fn remove(&self, pid: u32) {
        self.cache.write().unwrap().remove(&pid);
    }

    /// Evict expired entries
    fn evict_expired(&self, cache: &mut HashMap<u32, ProcCredState>) {
        let now = Instant::now();
        cache.retain(|_, v| now.duration_since(v.last_seen) < self.ttl);
    }

    /// Convert capability bitmask diff to names
    fn caps_diff(new_caps: u64, old_caps: u64) -> Vec<String> {
        let added_bits = new_caps & !old_caps;
        let mut caps = Vec::new();

        for i in 0..64 {
            if added_bits & (1 << i) != 0 {
                if let Some(name) = cap_name(i) {
                    caps.push(name.to_string());
                } else {
                    caps.push(format!("CAP_{}", i));
                }
            }
        }

        caps
    }

    /// Cache size for monitoring
    pub fn len(&self) -> usize {
        self.cache.read().unwrap().len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear cache (for testing)
    pub fn clear(&self) {
        self.cache.write().unwrap().clear();
    }
}

/// Map capability number to name
fn cap_name(cap: u32) -> Option<&'static str> {
    match cap {
        0 => Some("CAP_CHOWN"),
        1 => Some("CAP_DAC_OVERRIDE"),
        2 => Some("CAP_DAC_READ_SEARCH"),
        3 => Some("CAP_FOWNER"),
        4 => Some("CAP_FSETID"),
        5 => Some("CAP_KILL"),
        6 => Some("CAP_SETGID"),
        7 => Some("CAP_SETUID"),
        8 => Some("CAP_SETPCAP"),
        9 => Some("CAP_LINUX_IMMUTABLE"),
        10 => Some("CAP_NET_BIND_SERVICE"),
        11 => Some("CAP_NET_BROADCAST"),
        12 => Some("CAP_NET_ADMIN"),
        13 => Some("CAP_NET_RAW"),
        14 => Some("CAP_IPC_LOCK"),
        15 => Some("CAP_IPC_OWNER"),
        16 => Some("CAP_SYS_MODULE"),
        17 => Some("CAP_SYS_RAWIO"),
        18 => Some("CAP_SYS_CHROOT"),
        19 => Some("CAP_SYS_PTRACE"),
        20 => Some("CAP_SYS_PACCT"),
        21 => Some("CAP_SYS_ADMIN"),
        22 => Some("CAP_SYS_BOOT"),
        23 => Some("CAP_SYS_NICE"),
        24 => Some("CAP_SYS_RESOURCE"),
        25 => Some("CAP_SYS_TIME"),
        26 => Some("CAP_SYS_TTY_CONFIG"),
        27 => Some("CAP_MKNOD"),
        28 => Some("CAP_LEASE"),
        29 => Some("CAP_AUDIT_WRITE"),
        30 => Some("CAP_AUDIT_CONTROL"),
        31 => Some("CAP_SETFCAP"),
        32 => Some("CAP_MAC_OVERRIDE"),
        33 => Some("CAP_MAC_ADMIN"),
        34 => Some("CAP_SYSLOG"),
        35 => Some("CAP_WAKE_ALARM"),
        36 => Some("CAP_BLOCK_SUSPEND"),
        37 => Some("CAP_AUDIT_READ"),
        38 => Some("CAP_PERFMON"),
        39 => Some("CAP_BPF"),
        40 => Some("CAP_CHECKPOINT_RESTORE"),
        _ => None,
    }
}

// Global UID cache instance
lazy_static::lazy_static! {
    pub static ref UID_CACHE: UidCache = UidCache::default();
}

/// Update credentials for a process and get the change
pub fn update_process_creds(
    pid: u32,
    uid: u32,
    euid: u32,
    gid: u32,
    egid: u32,
    caps: u64,
) -> CredChange {
    UID_CACHE.update(pid, uid, euid, gid, egid, caps)
}

/// Get current credentials for a process
pub fn get_process_creds(pid: u32) -> Option<ProcCredState> {
    UID_CACHE.get(pid)
}

/// Remove process from cache (on exit)
pub fn remove_process(pid: u32) {
    UID_CACHE.remove(pid);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uid_before_after() {
        let cache = UidCache::new(100, Duration::from_secs(60));

        // Initial state - user 1000
        let change1 = cache.update(1234, 1000, 1000, 1000, 1000, 0);
        // First time, before should be same as after (no prior state)
        assert_eq!(change1.uid_after, 1000);
        assert_eq!(change1.euid_after, 1000);

        // Privilege escalation - become root
        let change2 = cache.update(1234, 1000, 0, 1000, 1000, 0);
        assert_eq!(change2.uid_before, 1000);
        assert_eq!(change2.uid_after, 1000);
        assert_eq!(change2.euid_before, 1000);
        assert_eq!(change2.euid_after, 0); // Now effective root
    }

    #[test]
    fn test_capability_tracking() {
        let cache = UidCache::new(100, Duration::from_secs(60));

        // Start with no caps
        let _ = cache.update(5678, 1000, 1000, 1000, 1000, 0);

        // Add CAP_NET_RAW (13) and CAP_SYS_ADMIN (21)
        let caps = (1 << 13) | (1 << 21);
        let change = cache.update(5678, 1000, 1000, 1000, 1000, caps);

        assert!(change.caps_added.contains(&"CAP_NET_RAW".to_string()));
        assert!(change.caps_added.contains(&"CAP_SYS_ADMIN".to_string()));
        assert!(change.caps_removed.is_empty());
    }

    #[test]
    fn test_cap_name() {
        assert_eq!(cap_name(0), Some("CAP_CHOWN"));
        assert_eq!(cap_name(21), Some("CAP_SYS_ADMIN"));
        assert_eq!(cap_name(39), Some("CAP_BPF"));
        assert_eq!(cap_name(100), None);
    }
}
