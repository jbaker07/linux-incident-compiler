//! process_injection sensor v2 - process injection and code cave detection
//! Sources: /proc/*/maps, /proc/*/status, /proc/*/attr/current (apparmor)
//! Detects: ptrace attachment, suspicious memory maps, RWX segments, anon exec

use crate::core::Event;
use crate::linux::event_builders;
use crate::linux::host::HostCtx;
use crate::linux::sensors_v2::common;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;

/// Collect process injection events
pub fn collect(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(pid_str) = path.file_name().and_then(|n| n.to_str()) {
                if let Ok(_) = pid_str.parse::<u32>() {
                    // Check for ptrace attachment
                    if let Ok(status) = fs::read_to_string(path.join("status")) {
                        for line in status.lines() {
                            if line.starts_with("TracerPid:") {
                                if let Some(tid) = line.split_whitespace().nth(1) {
                                    if tid != "0"
                                        && common::seen_once(
                                            "process_injection",
                                            &format!("tracer:{}", pid_str),
                                        )
                                    {
                                        let mut fields = BTreeMap::new();
                                        fields.insert("tracer_pid".to_string(), json!(tid));
                                        events.push(event_builders::event(
                                            host,
                                            "process_injection",
                                            "ptrace_attached",
                                            "warn",
                                            fields,
                                        ));
                                    }
                                }
                            }
                        }
                    }

                    // Invariant: RWX memory regions (code caves)
                    if let Ok(maps) = fs::read_to_string(path.join("maps")) {
                        for line in maps.lines() {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() >= 2 {
                                let perms = parts[1];
                                // Look for readable, writable, executable
                                if perms.contains('r') && perms.contains('w') && perms.contains('x')
                                {
                                    let path_part = parts.get(5).copied().unwrap_or("");
                                    // Anon RWX is suspicious
                                    if path_part.is_empty()
                                        || path_part == "[heap]"
                                        || path_part == "[stack]"
                                    {
                                        if common::rate_limit(
                                            "process_injection",
                                            &format!("rwx:{}", pid_str),
                                            60_000,
                                        ) {
                                            let mut fields = BTreeMap::new();
                                            fields.insert("pid".to_string(), json!(pid_str));
                                            fields.insert("perms".to_string(), json!(perms));
                                            fields.insert("region".to_string(), json!(path_part));
                                            events.push(event_builders::event(
                                                host,
                                                "process_injection",
                                                "anon_rwx_mem",
                                                "warn",
                                                fields,
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    events
}
