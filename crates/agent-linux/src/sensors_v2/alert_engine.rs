//! alert_engine sensor v2
//! Aggregates recent Events into "episode candidates" based on burst thresholds and co-occurrence
//! Episodes are multi-event correlations that suggest coordinated attack activity

use crate::core::event_keys;
use crate::core::Event;
use crate::linux::event_builders;
use crate::linux::host::HostCtx;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Maximum events to hold in-memory per cluster
const MAX_EVENTS_IN_MEMORY: usize = 1000;
/// Threshold for event burst (events in 5s window)
const BURST_THRESHOLD: usize = 10;
/// Time window in milliseconds
const WINDOW_MS: u64 = 5000;

/// Threshold for episode candidate: >=3 distinct kinds in 10m window
/// Reserved for future alert correlation; not yet used.
const EPISODE_KIND_THRESHOLD: usize = 3;
const EPISODE_WINDOW_MS: u64 = 600000; // 10 minutes

/// Episode candidate: deterministic hash-based ID from participating event keys
#[derive(Clone, Debug)]
pub struct EpisodeCandidate {
    episode_id: String,
    count_by_kind: BTreeMap<String, usize>,
    top_exe: Option<String>,
    top_user: Option<String>,
    top_remote_ip: Option<String>,
}

/// Collect alert_engine events - aggregates in-memory event bursts and episodes
pub fn collect(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Get the singleton event buffer (simulated)
    let event_count = get_event_buffer_snapshot().len();

    // Check 1: Burst detection - if many events in short window, emit alert_candidate
    if event_count >= BURST_THRESHOLD {
        // High-precision invariant: count must exceed threshold
        if super::common::rate_limit("alert_engine", "burst", WINDOW_MS) {
            let mut fields = BTreeMap::new();
            fields.insert("event_count".to_string(), json!(event_count));
            fields.insert("burst_threshold".to_string(), json!(BURST_THRESHOLD));
            fields.insert("window_ms".to_string(), json!(WINDOW_MS));

            events.push(event_builders::event(
                host,
                "alert_engine",
                "alert_candidate",
                "medium",
                fields,
            ));
        }
    }

    // Check 2: Heuristic - if buffer growing too fast, emit warning
    if event_count > MAX_EVENTS_IN_MEMORY {
        if super::common::rate_limit("alert_engine", "buffer_overflow", 30000) {
            let mut fields = BTreeMap::new();
            fields.insert("event_count".to_string(), json!(event_count));
            fields.insert("max_capacity".to_string(), json!(MAX_EVENTS_IN_MEMORY));

            events.push(event_builders::event(
                host,
                "alert_engine",
                "alert_candidate",
                "warn",
                fields,
            ));
        }
    }

    // Check 3: Episode candidate detection (would read from real buffer in production)
    // This is a stub that demonstrates the pattern
    if let Some(episode) = detect_episode_candidate(host) {
        if super::common::rate_limit(
            "alert_engine",
            &format!("episode_{}", episode.episode_id),
            600000,
        ) {
            let mut fields = BTreeMap::new();
            fields.insert("episode_id".to_string(), json!(episode.episode_id.clone()));
            fields.insert(
                "distinct_kinds".to_string(),
                json!(episode.count_by_kind.len()),
            );
            if let Some(exe) = episode.top_exe {
                fields.insert(event_keys::PROC_EXE.to_string(), json!(exe));
            }
            if let Some(user) = episode.top_user {
                fields.insert(event_keys::AUTH_USER.to_string(), json!(user));
            }
            if let Some(ip) = episode.top_remote_ip {
                fields.insert(event_keys::NET_REMOTE_IP.to_string(), json!(ip));
            }

            events.push(event_builders::event(
                host,
                "alert_engine",
                "episode_candidate",
                "high",
                fields,
            ));
        }
    }

    events
}

/// Simulate detecting an episode candidate from the event buffer
fn detect_episode_candidate(_host: &HostCtx) -> Option<EpisodeCandidate> {
    // In production, this would analyze the actual event buffer
    // For now, return None to avoid spurious detections
    None
}

/// Generate deterministic episode ID from event hashes
/// Reserved for future alert correlation; not yet used.
fn episode_id(event_keys: &[String]) -> String {
    let mut hasher = Sha256::new();
    for key in event_keys {
        hasher.update(key.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

/// Simulate reading in-memory event buffer (would be populated by capture layer)
fn get_event_buffer_snapshot() -> Vec<Event> {
    // In production, this would read from a shared in-memory buffer
    // For now, return empty - the capture layer would populate this
    Vec::new()
}
