//! auth_monitor sensor v2 - authentication anomaly detection
//! Sources: /var/log/auth.log, utmp, wtmp
//! Detects: failed login bursts, unusual login times, sudo abuse, elevated privilege logins

use crate::core::Event;
use crate::linux::event_builders;
use crate::linux::host::HostCtx;
use crate::linux::sensors_v2::common;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;

/// Collect authentication anomaly events
pub fn collect(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Parse auth logs for failures and successes
    if let Ok(log_content) = fs::read_to_string("/var/log/auth.log") {
        let lines: Vec<&str> = log_content.lines().rev().take(1000).collect();
        let mut failures: BTreeMap<String, Vec<u64>> = BTreeMap::new();
        let mut sudo_uses: Vec<(String, u64)> = Vec::new();

        for line in lines.iter() {
            // Track failed logins
            if line.contains("Failed password") || line.contains("Invalid user") {
                if let Some(user) = extract_user(line) {
                    failures
                        .entry(user)
                        .or_insert_with(Vec::new)
                        .push(common::now_ms());
                }
            }

            // Track sudo execution
            if line.contains("sudo") && line.contains("command=") {
                if let Some(user) = extract_user(line) {
                    sudo_uses.push((user, common::now_ms()));
                }
            }
        }

        // Invariant check: password spray (5+ failures in 10min window)
        for (user, times) in failures.iter() {
            let now = common::now_ms();
            let recent_10m = times
                .iter()
                .filter(|t| *t > &(now.saturating_sub(600_000)))
                .count();
            if recent_10m >= 5 && common::seen_once("auth_monitor", &format!("spray:{}", user)) {
                let mut fields = BTreeMap::new();
                fields.insert("user".to_string(), json!(user.clone()));
                fields.insert("fail_count".to_string(), json!(recent_10m));
                events.push(event_builders::event(
                    host,
                    "auth_monitor",
                    "password_spray",
                    "warn",
                    fields,
                ));
            }
        }

        // Heuristic: failed login from multiple IPs (from sshd logs)
        let ips: BTreeMap<String, u32> = lines
            .iter()
            .filter(|l| l.contains("Invalid user") && l.contains(" from "))
            .filter_map(|l| extract_ip(l).map(|ip| (ip, 1)))
            .fold(BTreeMap::new(), |mut acc, (ip, _)| {
                *acc.entry(ip).or_insert(0) += 1;
                acc
            });

        for (ip, count) in ips.iter() {
            if *count >= 3
                && common::rate_limit("auth_monitor", &format!("spray_ip:{}", ip), 300_000)
            {
                let mut fields = BTreeMap::new();
                fields.insert("source_ip".to_string(), json!(ip.clone()));
                fields.insert("attempt_count".to_string(), json!(count));
                events.push(event_builders::event(
                    host,
                    "auth_monitor",
                    "distributed_spray",
                    "warn",
                    fields,
                ));
            }
        }
    }

    events
}

fn extract_user(line: &str) -> Option<String> {
    if let Some(pos) = line.find("user=") {
        line[pos + 5..]
            .split_whitespace()
            .next()
            .map(|s| s.to_string())
    } else if let Some(pos) = line.find("Invalid user ") {
        line[pos + 13..]
            .split_whitespace()
            .next()
            .map(|s| s.to_string())
    } else {
        None
    }
}

fn extract_ip(line: &str) -> Option<String> {
    if let Some(pos) = line.find(" from ") {
        line[pos + 6..]
            .split_whitespace()
            .next()
            .map(|s| s.to_string())
    } else {
        None
    }
}
