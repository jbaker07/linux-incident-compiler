//! job_sched_monitor sensor v2
//! Cron + systemd timer/unit deltas and suspicious command tokens

use crate::core::Event;
use crate::linux::event_builders;
use crate::linux::host::HostCtx;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// Collect job_sched_monitor events
pub fn collect(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Check 1: High-precision invariant - cron job changes
    events.extend(detect_cron_changes(host));

    // Check 2: Heuristic - systemd timer anomalies
    events.extend(detect_systemd_anomalies(host));

    events
}

fn detect_cron_changes(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Check cron directories
    let cron_dirs = vec![
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
    ];

    for cron_dir in cron_dirs {
        if let Ok(entries) = fs::read_dir(cron_dir) {
            for entry in entries.flatten() {
                if let Ok(path) = entry.path().into_os_string().into_string() {
                    if let Ok(content) = fs::read_to_string(&path) {
                        // Check for suspicious command tokens
                        if has_suspicious_tokens(&content) {
                            let key = format!("cron:{}", path);
                            if super::common::rate_limit("job_sched_monitor", &key, 3600000) {
                                let mut fields = BTreeMap::new();
                                fields.insert("cron_file".to_string(), json!(path));
                                fields.insert("contains_suspicious".to_string(), json!(true));

                                events.push(event_builders::event(
                                    host,
                                    "job_sched_monitor",
                                    "suspicious_cron",
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

    // Check user crontabs
    if let Ok(entries) = fs::read_dir("/var/spool/cron/crontabs") {
        for entry in entries.flatten() {
            if let Ok(path) = entry.path().into_os_string().into_string() {
                if let Ok(content) = fs::read_to_string(&path) {
                    let job_count = content
                        .lines()
                        .filter(|l| !l.starts_with('#') && !l.is_empty())
                        .count();

                    if job_count > 0 {
                        let key = format!("user_cron:{}", path);
                        if super::common::rate_limit("job_sched_monitor", &key, 3600000) {
                            let mut fields = BTreeMap::new();
                            fields.insert("user_crontab".to_string(), json!(path));
                            fields.insert("job_count".to_string(), json!(job_count));

                            events.push(event_builders::event(
                                host,
                                "job_sched_monitor",
                                "user_cron",
                                "info",
                                fields,
                            ));
                        }
                    }
                }
            }
        }
    }

    events
}

fn detect_systemd_anomalies(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Check systemd user units
    if let Ok(home) = std::env::var("HOME") {
        let unit_dirs = vec![
            format!("{}/.config/systemd/user", home),
            "/etc/systemd/system".to_string(),
            "/usr/lib/systemd/system".to_string(),
        ];

        for unit_dir in unit_dirs {
            let path = Path::new(&unit_dir);
            if path.exists() {
                if let Ok(entries) = fs::read_dir(&unit_dir) {
                    for entry in entries.flatten() {
                        if let Ok(path) = entry.path().into_os_string().into_string() {
                            if path.ends_with(".timer") || path.ends_with(".service") {
                                if let Ok(content) = fs::read_to_string(&path) {
                                    if has_suspicious_tokens(&content) {
                                        let key = format!("systemd:{}", path);
                                        if super::common::rate_limit(
                                            "job_sched_monitor",
                                            &key,
                                            3600000,
                                        ) {
                                            let mut fields = BTreeMap::new();
                                            fields.insert("unit_file".to_string(), json!(path));
                                            fields.insert(
                                                "contains_suspicious".to_string(),
                                                json!(true),
                                            );

                                            events.push(event_builders::event(
                                                host,
                                                "job_sched_monitor",
                                                "suspicious_systemd",
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

/// Check for suspicious command tokens in job scheduler content
fn has_suspicious_tokens(content: &str) -> bool {
    let suspicious = vec![
        "curl",
        "wget",
        "nc",
        "ncat",
        "telnet",
        "bash -i",
        "/bin/bash -i",
        "sh -i",
        "/bin/sh -i",
        "&& ",
        "; ",
        "| ",
        "base64",
        "decode",
        "python",
        "perl",
        "ruby",
    ];

    suspicious.iter().any(|token| content.contains(token))
}
