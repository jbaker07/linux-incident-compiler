//! mem_scan sensor v2
//! /proc/pid/maps RWX, anon exec, W->X heuristics; rate-limit per pid

use crate::core::event_keys;
use crate::core::Event;
use crate::linux::event_builders;
use crate::linux::host::HostCtx;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;

/// Collect mem_scan events - detect suspicious memory mappings
pub fn collect(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Check 1: High-precision invariant - RWX memory regions
    events.extend(detect_rwx_regions(host));

    // Check 2: Heuristic - writable to executable transitions
    events.extend(detect_wx_transitions(host));

    events
}

fn detect_rwx_regions(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(filename) = entry.file_name().into_string() {
                if let Ok(pid) = filename.parse::<u32>() {
                    let maps_path = format!("/proc/{}/maps", pid);
                    if let Ok(content) = fs::read_to_string(&maps_path) {
                        let mut has_rwx = false;
                        let mut rwx_count = 0;

                        for line in content.lines() {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() < 2 {
                                continue;
                            }

                            let perms = parts[1];

                            // Check for RWX (read + write + execute)
                            if perms.contains('r') && perms.contains('w') && perms.contains('x') {
                                has_rwx = true;
                                rwx_count += 1;

                                // Check if anonymous (high suspicion)
                                let map_type = parts.get(5).copied();
                                let is_anon = map_type
                                    .map(|p| p == "[anon]" || p == "[heap]")
                                    .unwrap_or(false);

                                if is_anon {
                                    let key = format!("anon_rwx:{}:{}", pid, line);
                                    if super::common::seen_once("mem_scan", &key) {
                                        let mut fields = BTreeMap::new();
                                        fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
                                        fields.insert(
                                            event_keys::MEM_PERMS.to_string(),
                                            json!(perms),
                                        );
                                        fields.insert(
                                            event_keys::MEM_ADDRESS.to_string(),
                                            json!(parts[0]),
                                        );
                                        if let Some(map_type) = map_type {
                                            fields.insert(
                                                event_keys::MEM_TYPE.to_string(),
                                                json!(map_type.to_string()),
                                            );
                                        }

                                        events.push(event_builders::event(
                                            host,
                                            "mem_scan",
                                            "rwx_memory",
                                            "high",
                                            fields,
                                        ));
                                    }
                                }
                            }
                        }

                        // Rate-limit summary if multiple RWX regions
                        if has_rwx && rwx_count > 1 {
                            let key = format!("rwx_summary:{}", pid);
                            if super::common::rate_limit("mem_scan", &key, 60000) {
                                let mut fields = BTreeMap::new();
                                fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
                                fields.insert("rwx_region_count".to_string(), json!(rwx_count));

                                events.push(event_builders::event(
                                    host,
                                    "mem_scan",
                                    "multiple_rwx",
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

fn detect_wx_transitions(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(filename) = entry.file_name().into_string() {
                if let Ok(pid) = filename.parse::<u32>() {
                    let maps_path = format!("/proc/{}/maps", pid);
                    if let Ok(content) = fs::read_to_string(&maps_path) {
                        let mut last_addr = 0u64;
                        let mut last_was_writable = false;
                        let mut wx_transitions = 0;

                        for line in content.lines() {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() < 2 {
                                continue;
                            }

                            if let Some((addr_str, _)) = parts[0].split_once('-') {
                                if let Ok(addr) = u64::from_str_radix(addr_str, 16) {
                                    let perms = parts[1];
                                    let is_writable = perms.contains('w');
                                    let is_exec = perms.contains('x');

                                    // Detect W->X transition in consecutive regions
                                    if last_was_writable && is_exec && addr == last_addr {
                                        wx_transitions += 1;
                                    }

                                    last_addr = addr;
                                    last_was_writable = is_writable;
                                }
                            }
                        }

                        // Report if multiple W->X transitions detected
                        if wx_transitions > 0 {
                            let key = format!("wx_transition:{}:{}", pid, wx_transitions);
                            if super::common::rate_limit("mem_scan", &key, 60000) {
                                let mut fields = BTreeMap::new();
                                fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
                                fields.insert(
                                    "wx_transition_count".to_string(),
                                    json!(wx_transitions),
                                );

                                events.push(event_builders::event(
                                    host,
                                    "mem_scan",
                                    "wx_transition",
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
