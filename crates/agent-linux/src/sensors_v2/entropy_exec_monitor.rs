//! entropy_exec_monitor sensor v2
//! Detects executable files from writable paths with quick entropy/size heuristics

use crate::core::Event;
use crate::linux::event_builders;
use crate::linux::host::HostCtx;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;

/// Collect entropy_exec_monitor events
pub fn collect(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Check 1: High-precision invariant - execution from writable paths
    events.extend(detect_exec_from_writable(host));

    // Check 2: Heuristic - quick entropy heuristic on executable files
    events.extend(detect_suspicious_executables(host));

    events
}

fn detect_exec_from_writable(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Writable directories that shouldn't contain executables
    let writable_dirs = vec!["/tmp", "/var/tmp", "/dev/shm"];

    for dir_path in writable_dirs {
        if let Ok(entries) = fs::read_dir(dir_path) {
            for entry in entries.flatten() {
                if let Ok(path) = entry.path().into_os_string().into_string() {
                    if let Ok(meta) = fs::metadata(&path) {
                        if meta.is_file() {
                            // Check if executable
                            #[cfg(unix)]
                            let is_exec = {
                                use std::os::unix::fs::PermissionsExt;
                                meta.permissions().mode() & 0o111 != 0
                            };
                            #[cfg(not(unix))]
                            let is_exec = false;

                            if is_exec {
                                let key = format!("exec:{}", path);
                                if super::common::seen_once("entropy_exec_monitor", &key) {
                                    let mut fields = BTreeMap::new();
                                    fields.insert("path".to_string(), json!(path.clone()));
                                    fields.insert("directory".to_string(), json!(dir_path));
                                    fields.insert("size_bytes".to_string(), json!(meta.len()));

                                    events.push(event_builders::event(
                                        host,
                                        "entropy_exec_monitor",
                                        "exec_from_writable",
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

fn detect_suspicious_executables(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(filename) = entry.file_name().into_string() {
                if let Ok(pid) = filename.parse::<u32>() {
                    let exe_path = format!("/proc/{}/exe", pid);
                    if let Ok(exe) = fs::read_link(&exe_path) {
                        if let Some(exe_str) = exe.to_str() {
                            // Check if exe is in writable location
                            if exe_str.starts_with("/tmp")
                                || exe_str.starts_with("/var/tmp")
                                || exe_str.starts_with("/dev/shm")
                            {
                                // Try to read and calculate entropy
                                if let Ok(content) = fs::read(exe_str) {
                                    let size_ratio = content.len() as f32 / 1024.0;
                                    let entropy = quick_entropy_heuristic(&content);

                                    // Heuristic: small size + moderate entropy = suspicious
                                    if content.len() < 50_000 && entropy > 5.0 {
                                        let key = format!("suspicious:{}", pid);
                                        if super::common::rate_limit(
                                            "entropy_exec_monitor",
                                            &key,
                                            60000,
                                        ) {
                                            let mut fields = BTreeMap::new();
                                            fields.insert("pid".to_string(), json!(pid));
                                            fields.insert("exe".to_string(), json!(exe_str));
                                            fields.insert("size_kb".to_string(), json!(size_ratio));
                                            fields.insert("entropy".to_string(), json!(entropy));

                                            events.push(event_builders::event(
                                                host,
                                                "entropy_exec_monitor",
                                                "suspicious_exec",
                                                "medium",
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

/// Quick entropy estimate (sample first 1KB)
fn quick_entropy_heuristic(data: &[u8]) -> f32 {
    let sample_size = std::cmp::min(1024, data.len());
    let sample = &data[..sample_size];

    let mut freq = [0u32; 256];
    for &byte in sample {
        freq[byte as usize] += 1;
    }

    let len = sample.len() as f32;
    let mut entropy = 0.0f32;

    for &count in &freq {
        if count > 0 {
            let p = count as f32 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}
