//! Network watch sensor - network connection snapshots
//! Pure event emitter, no side effects

use crate::core::Event;
use crate::linux::event_builders;
use crate::linux::host::HostCtx;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;

/// Collect network connection events
pub fn collect(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Sample connections from /proc/net/tcp
    if let Ok(lines) = fs::read_to_string("/proc/net/tcp") {
        for (idx, line) in lines.lines().enumerate() {
            if idx == 0 || idx > 100 {
                continue;
            } // Skip header, limit to 100 samples

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                if let Some(event) = parse_tcp_line(host, &parts) {
                    events.push(event);
                }
            }
        }
    }

    events
}

fn parse_tcp_line(host: &HostCtx, parts: &[&str]) -> Option<Event> {
    // Format: sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
    let local_addr = parts[1];
    let rem_addr = parts[2];
    let state = parts[3];

    let mut fields = BTreeMap::new();
    fields.insert("local_addr".to_string(), json!(local_addr));
    fields.insert("remote_addr".to_string(), json!(rem_addr));
    fields.insert("state".to_string(), json!(state));

    Some(event_builders::event(
        host,
        "net_watch",
        "network",
        "info",
        fields,
    ))
}
