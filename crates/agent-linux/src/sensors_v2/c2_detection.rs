//! Linux C2 detection with bounded state
//! Tracks new remote IPs per process and bursty connection patterns
//! State: Arc<Mutex<C2State>> managed by capture_linux_rotating.rs

use crate::core::{event_keys, Event};
use crate::linux::event_builders;
use crate::linux::host::HostCtx;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Bounded C2 detection state (TTL managed by capture)
#[derive(Debug, Clone)]
pub struct C2State {
    /// Map: (pid, remote_ip) -> timestamp_ms (last seen)
    pub new_remotes: BTreeMap<(u32, String), i64>,
    /// Map: (pid, remote_ip) -> (connect_count, window_start_ms)
    pub burst_tracker: BTreeMap<(u32, String), (u32, i64)>,
    /// Last cleanup timestamp
    pub last_cleanup_ms: i64,
}

impl C2State {
    pub fn new() -> Self {
        Self {
            new_remotes: BTreeMap::new(),
            burst_tracker: BTreeMap::new(),
            last_cleanup_ms: now_ms(),
        }
    }

    /// Detect new remote IP per process (never seen before)
    pub fn is_new_remote(&mut self, pid: u32, remote_ip: &str) -> bool {
        let key = (pid, remote_ip.to_string());
        if self.new_remotes.contains_key(&key) {
            false
        } else {
            self.new_remotes.insert(key, now_ms());
            true
        }
    }

    /// Detect burst: >= 5 connects to same (pid, remote_ip) in 5 seconds
    pub fn is_burst_connect(&mut self, pid: u32, remote_ip: &str) -> bool {
        let key = (pid, remote_ip.to_string());
        let now = now_ms();
        let window_duration_ms = 5000i64;
        let burst_threshold = 5u32;

        if let Some((count, window_start)) = self.burst_tracker.get_mut(&key) {
            if now - *window_start < window_duration_ms {
                // Still in window: increment count
                *count += 1;
                *count >= burst_threshold
            } else {
                // Window expired: reset
                *window_start = now;
                *count = 1;
                false
            }
        } else {
            // New tracker entry
            self.burst_tracker.insert(key, (1, now));
            false
        }
    }

    /// Cleanup old entries (TTL: 30 minutes for new_remotes, 5 seconds for burst_tracker)
    pub fn cleanup(&mut self) {
        let now = now_ms();
        let new_remote_ttl_ms = 30 * 60 * 1000i64; // 30 minutes
        let burst_ttl_ms = 5 * 1000i64; // 5 seconds

        // Clean new_remotes
        self.new_remotes
            .retain(|_, ts| now - ts < new_remote_ttl_ms);

        // Clean burst_tracker
        self.burst_tracker
            .retain(|_, (_, window_start)| now - window_start < burst_ttl_ms);

        self.last_cleanup_ms = now;
    }
}

/// Detect C2 signals based on bounded state (called from capture loop)
pub fn detect_c2(host: &HostCtx, state: &Arc<Mutex<C2State>>, net_events: &[Event]) -> Vec<Event> {
    let mut events = Vec::new();

    if let Ok(mut s) = state.lock() {
        // Periodically cleanup (every 10 seconds)
        let now = now_ms();
        if now - s.last_cleanup_ms > 10000 {
            s.cleanup();
        }

        for evt in net_events {
            // Only process net_connect events
            if !evt.tag_contains("network") || !evt.tag_contains("connect") {
                continue;
            }

            let pid = evt
                .fields
                .get(event_keys::PROC_PID)
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;

            let uid = evt
                .fields
                .get(event_keys::PROC_UID)
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;

            let exe = evt
                .fields
                .get(event_keys::PROC_EXE)
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();

            let remote_ip = evt
                .fields
                .get(event_keys::NET_REMOTE_IP)
                .and_then(|v| v.as_str())
                .unwrap_or("0.0.0.0")
                .to_string();

            let remote_port = evt
                .fields
                .get(event_keys::NET_REMOTE_PORT)
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u16;

            // Check: is this a private/link-local IP? (skip RFC1918 noise)
            let is_private = evt
                .fields
                .get("is_private_ip")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);

            if is_private {
                continue; // Skip private IPs
            }

            let mut reason = String::new();

            // Condition A: new remote IP (first time this pid contacts this IP)
            if s.is_new_remote(pid, &remote_ip) {
                reason = "new_remote".to_string();
            }

            // Condition B: bursty connects
            if s.is_burst_connect(pid, &remote_ip) {
                reason = if reason.is_empty() {
                    "burst".to_string()
                } else {
                    format!("{},burst", reason)
                };
            }

            // Only emit if one of the conditions triggered
            if !reason.is_empty() {
                let mut fields = BTreeMap::new();
                fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
                fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
                fields.insert(event_keys::PROC_EXE.to_string(), json!(exe));
                fields.insert(event_keys::NET_REMOTE_IP.to_string(), json!(remote_ip));
                fields.insert(event_keys::NET_REMOTE_PORT.to_string(), json!(remote_port));
                fields.insert("reason".to_string(), json!(reason));

                let mut ev =
                    event_builders::event(host, "attack_surface", "c2_suspected", "high", fields);
                ev.tags
                    .extend(vec!["command_control".to_string(), "heuristic".to_string()]);
                events.push(ev);
            }
        }
    }

    events
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
