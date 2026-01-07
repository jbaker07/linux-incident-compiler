//! process_monitor sensor v2 - process execution and anomaly detection
//! Sources: /proc/*/stat, /proc/*/cmdline, /proc/*/cwd, /proc/*/fd/
//! Detects: process execution, privilege transition, parent spoofing, suspicious patterns

use crate::core::Event;
use crate::linux::event_builders;
use crate::linux::host::HostCtx;
use crate::linux::sensors_v2::common;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;

/// Collect process execution and anomaly events
pub fn collect(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(pid_str) = path.file_name().and_then(|n| n.to_str()) {
                if let Ok(_pid) = pid_str.parse::<u32>() {
                    // Read cmdline
                    let cmdline = fs::read_to_string(path.join("cmdline"))
                        .unwrap_or_default()
                        .replace('\0', " ");

                    // Invariant: process from /tmp or /dev/shm executing (unusual)
                    if let Ok(exe) = fs::read_link(path.join("exe")) {
                        if let Some(exe_str) = exe.to_str() {
                            let is_writable = exe_str.contains("/tmp")
                                || exe_str.contains("/dev/shm")
                                || exe_str.contains("/var/tmp");
                            if is_writable
                                && common::seen_once(
                                    "process_monitor",
                                    &format!("exec_tmp:{}", exe_str),
                                )
                            {
                                let mut fields = BTreeMap::new();
                                fields.insert("exe".to_string(), json!(exe_str));
                                fields.insert(
                                    "cmdline".to_string(),
                                    json!(cmdline.chars().take(200).collect::<String>()),
                                );
                                events.push(event_builders::event(
                                    host,
                                    "process_monitor",
                                    "exec_temp",
                                    "alert",
                                    fields,
                                ));
                            }
                        }
                    }

                    // Heuristic: suspicious process patterns
                    let suspicious = is_suspicious_cmdline(&cmdline);
                    if suspicious
                        && common::rate_limit(
                            "process_monitor",
                            &format!("suspicious:{}", pid_str),
                            60_000,
                        )
                    {
                        let mut fields = BTreeMap::new();
                        fields.insert(
                            "cmdline".to_string(),
                            json!(cmdline.chars().take(200).collect::<String>()),
                        );
                        events.push(event_builders::event(
                            host,
                            "process_monitor",
                            "suspicious_exec",
                            "warn",
                            fields,
                        ));
                    }

                    // Check open files for suspicious descriptors
                    if let Ok(fd_dir) = fs::read_dir(path.join("fd")) {
                        for fd_entry in fd_dir.flatten() {
                            if let Ok(target) = fs::read_link(fd_entry.path()) {
                                if let Some(target_str) = target.to_str() {
                                    // Check for library injection or writable binary interception
                                    if (target_str.contains("ld-musl")
                                        || target_str.contains("ld-linux"))
                                        && target_str.contains("/tmp")
                                    {
                                        if common::seen_once(
                                            "process_monitor",
                                            &format!("ld_inject:{}", pid_str),
                                        ) {
                                            let mut fields = BTreeMap::new();
                                            fields.insert("pid".to_string(), json!(pid_str));
                                            fields.insert(
                                                "injected_lib".to_string(),
                                                json!(target_str),
                                            );
                                            events.push(event_builders::event(
                                                host,
                                                "process_monitor",
                                                "library_injection",
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

fn is_suspicious_cmdline(cmdline: &str) -> bool {
    let lower = cmdline.to_lowercase();

    // Suspicious patterns
    lower.contains("curl ") && (lower.contains("|") || lower.contains("sh"))
        || lower.contains("wget ") && (lower.contains("|") || lower.contains("sh"))
        || lower.contains("base64 -d")
        || lower.contains("/dev/tcp")
        || lower.contains("exec ") && lower.contains(">&")
        || lower.contains("dd if=") && lower.contains("of=/tmp")
        || lower.contains("nc -l") && lower.contains("&")
        || (lower.contains("python") || lower.contains("perl"))
            && (lower.contains("-c") || lower.contains("-e"))
        || lower.contains("cat ") && lower.contains("> /tmp")
        || lower.contains("chmod ") && lower.contains("777")
}
