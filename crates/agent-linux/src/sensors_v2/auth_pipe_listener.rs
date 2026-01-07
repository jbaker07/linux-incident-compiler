//! auth_pipe_listener sensor v2
//! Reads from optional FIFO/Unix socket for auth events, parses JSONL -> Events

use crate::core::Event;
use crate::linux::event_builders;
use crate::linux::host::HostCtx;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::FileTypeExt;

const AUTH_PIPE_PATH: &str = "/var/run/edr-auth.fifo";

/// Collect auth_pipe_listener events - reads from FIFO if available
pub fn collect(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Check if FIFO exists
    match fs::metadata(AUTH_PIPE_PATH) {
        Ok(meta) => {
            if !meta.file_type().is_fifo() {
                // Path exists but is not FIFO - emit warning once
                if super::common::seen_once("auth_pipe_listener", "not_fifo") {
                    return vec![event_builders::sensor_failure(
                        host,
                        "auth_pipe_listener",
                        &format!("{} exists but is not a FIFO", AUTH_PIPE_PATH),
                    )];
                }
                return events;
            }
        }
        Err(_) => {
            // FIFO doesn't exist - this is normal if auth system not configured
            return events;
        }
    }

    // Try to read from FIFO (non-blocking best-effort)
    // Note: In production, would use non-blocking I/O or inotify
    if let Ok(content) = fs::read_to_string(AUTH_PIPE_PATH) {
        for line in content.lines() {
            if line.is_empty() {
                continue;
            }

            // Check 1: High-precision invariant - validate JSONL format
            if let Ok(json_obj) = serde_json::from_str::<serde_json::Value>(line) {
                // Check 2: Heuristic - look for suspicious auth patterns
                let has_failure = json_obj
                    .get("status")
                    .and_then(|v| v.as_str())
                    .map(|s| s.contains("failed") || s.contains("error"))
                    .unwrap_or(false);

                let username = json_obj
                    .get("user")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");

                // Rate limit per username
                if has_failure
                    && super::common::rate_limit(
                        "auth_pipe_listener",
                        &format!("fail:{}", username),
                        5000,
                    )
                {
                    let mut fields = BTreeMap::new();
                    fields.insert("user".to_string(), json!(username));
                    fields.insert("source".to_string(), json!("fifo"));

                    for (key, val) in json_obj
                        .as_object()
                        .unwrap_or(&Default::default())
                        .iter()
                        .take(5)
                    {
                        fields.insert(key.clone(), val.clone());
                    }

                    events.push(event_builders::event(
                        host,
                        "auth_pipe_listener",
                        "auth_event",
                        if has_failure { "medium" } else { "info" },
                        fields,
                    ));
                }
            }
        }
    }

    events
}
