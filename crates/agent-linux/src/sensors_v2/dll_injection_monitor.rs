//! dll_injection_monitor sensor v2 (Linux LD_PRELOAD analog)
//! Detects LD_PRELOAD/LD_AUDIT injection, suspicious map patterns

use crate::core::Event;
use crate::linux::event_builders;
use crate::linux::host::HostCtx;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;

/// Collect dll_injection_monitor events - detect LD_PRELOAD and suspicious mmap patterns
pub fn collect(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Check 1: High-precision invariant - detect LD_PRELOAD in process environment
    events.extend(detect_ld_preload(host));

    // Check 2: Heuristic - detect suspicious mmap patterns (RWX, anon exec)
    events.extend(detect_suspicious_maps(host));

    events
}

fn detect_ld_preload(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(filename) = entry.file_name().into_string() {
                if let Ok(pid) = filename.parse::<u32>() {
                    let environ_path = format!("/proc/{}/environ", pid);
                    if let Ok(bytes) = fs::read(&environ_path) {
                        let environ = String::from_utf8_lossy(&bytes);

                        // Check for LD_PRELOAD, LD_AUDIT, LD_LIBRARY_PATH manipulation
                        let suspicious_vars = vec!["LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"];

                        for var in suspicious_vars {
                            if environ.contains(&format!("{}=", var)) {
                                let key = format!("{}:{}", var, pid);
                                if super::common::seen_once("dll_injection_monitor", &key) {
                                    let mut fields = BTreeMap::new();
                                    fields.insert("pid".to_string(), json!(pid));
                                    fields.insert("env_var".to_string(), json!(var));

                                    // Extract value (first 256 chars for safety)
                                    if let Some(start) = environ.find(&format!("{}=", var)) {
                                        let remainder = &environ[start + var.len() + 1..];
                                        if let Some(end) = remainder.find('\0') {
                                            let value = &remainder[..std::cmp::min(end, 256)];
                                            fields.insert("value".to_string(), json!(value));
                                        }
                                    }

                                    events.push(event_builders::event(
                                        host,
                                        "dll_injection_monitor",
                                        "ld_injection",
                                        "high",
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

    events
}

fn detect_suspicious_maps(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(filename) = entry.file_name().into_string() {
                if let Ok(pid) = filename.parse::<u32>() {
                    let maps_path = format!("/proc/{}/maps", pid);
                    if let Ok(content) = fs::read_to_string(&maps_path) {
                        let mut anon_rwx_count = 0;

                        for line in content.lines() {
                            // Format: address perms ...
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() >= 2 {
                                let perms = parts[1];

                                // Check for RWX (suspicious)
                                if perms.contains('r') && perms.contains('w') && perms.contains('x')
                                {
                                    // Check if anonymous (no file backing)
                                    let is_anon = parts
                                        .get(5)
                                        .map(|p| {
                                            *p == "[anon]" || *p == "[heap]" || *p == "[stack]"
                                        })
                                        .unwrap_or(false);

                                    if is_anon {
                                        anon_rwx_count += 1;
                                    }
                                }
                            }
                        }

                        // Emit if multiple RWX anonymous regions found
                        if anon_rwx_count >= 2 {
                            let key = format!("rwx:{}", pid);
                            if super::common::rate_limit("dll_injection_monitor", &key, 60000) {
                                let mut fields = BTreeMap::new();
                                fields.insert("pid".to_string(), json!(pid));
                                fields.insert("anon_rwx_count".to_string(), json!(anon_rwx_count));

                                events.push(event_builders::event(
                                    host,
                                    "dll_injection_monitor",
                                    "suspicious_mmap",
                                    "high",
                                    fields,
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    events
}
