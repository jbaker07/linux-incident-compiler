//! password_spray sensor v2
//! Derive from auth_monitor shared counters across many users; emit password_spray

use crate::core::event_keys;
use crate::core::Event;
use crate::linux::event_builders;
use crate::linux::host::HostCtx;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::process::Command;

/// Threshold for password spray detection (failed attempts per source)
const SPRAY_THRESHOLD: usize = 5;
/// Time window for detection in milliseconds
const SPRAY_WINDOW_MS: u64 = 300000; // 5 minutes

/// Collect password_spray events
pub fn collect(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Check 1: High-precision invariant - rapid failed logins from single source
    events.extend(detect_spray_from_logs(host));

    // Check 2: Heuristic - unusual failed login patterns
    events.extend(detect_spray_patterns(host));

    events
}

fn detect_spray_from_logs(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Check auth logs for rapid failures
    let log_paths = vec!["/var/log/auth.log", "/var/log/secure", "/var/log/messages"];

    for log_path in log_paths {
        if let Ok(content) = fs::read_to_string(log_path) {
            // Count failed logins per remote IP
            let mut failures_per_ip: std::collections::HashMap<String, usize> =
                std::collections::HashMap::new();

            for line in content.lines().rev().take(500) {
                // Look for failed auth patterns
                if line.contains("Failed password") || line.contains("Authentication failure") {
                    // Try to extract source IP
                    if let Some(ip) = extract_ip_from_log(line) {
                        *failures_per_ip.entry(ip).or_insert(0) += 1;
                    }
                }
            }

            // Report if any source exceeds threshold
            for (source_ip, count) in failures_per_ip {
                if count >= SPRAY_THRESHOLD {
                    let key = format!("spray:{}:{}", log_path, source_ip);
                    if super::common::rate_limit("password_spray", &key, SPRAY_WINDOW_MS) {
                        let mut fields = BTreeMap::new();
                        fields.insert(event_keys::NET_REMOTE_IP.to_string(), json!(source_ip));
                        fields.insert("failed_attempts".to_string(), json!(count));
                        fields.insert(event_keys::THRESHOLD.to_string(), json!(SPRAY_THRESHOLD));
                        fields.insert("log_file".to_string(), json!(log_path));

                        events.push(event_builders::event(
                            host,
                            "password_spray",
                            "password_spray",
                            "high",
                            fields,
                        ));
                    }
                }
            }
        }
    }

    events
}

fn detect_spray_patterns(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Use lastb to check failed login attempts
    if let Ok(output) = Command::new("lastb").arg("-t").arg("1h").output() {
        if output.status.success() {
            let output_str = String::from_utf8_lossy(&output.stdout);

            // Count failures per source
            let mut failures_per_source: std::collections::HashMap<String, usize> =
                std::collections::HashMap::new();

            for line in output_str.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let source = parts.get(2..4).map(|p| p.join(" ")).unwrap_or_default();
                    *failures_per_source.entry(source).or_insert(0) += 1;
                }
            }

            // Report patterns
            for (source, count) in failures_per_source {
                if count >= SPRAY_THRESHOLD {
                    let key = format!("spray_pattern:{}", source);
                    if super::common::rate_limit("password_spray", &key, SPRAY_WINDOW_MS) {
                        let mut fields = BTreeMap::new();
                        fields.insert(event_keys::NET_REMOTE_IP.to_string(), json!(source));
                        fields.insert("failed_count".to_string(), json!(count));

                        events.push(event_builders::event(
                            host,
                            "password_spray",
                            "password_spray",
                            "high",
                            fields,
                        ));
                    }
                }
            }
        }
    }

    events
}

/// Extract IP address from auth log line
fn extract_ip_from_log(line: &str) -> Option<String> {
    // Look for common IP patterns in logs
    let parts: Vec<&str> = line.split_whitespace().collect();

    for part in parts {
        // Simple IPv4 detection
        if part.contains('.') && part.split('.').count() == 4 {
            let octets: Vec<&str> = part.split('.').collect();
            if octets.len() == 4 {
                // Check if all octets are valid numbers
                if let (Ok(_), Ok(_), Ok(_), Ok(_)) = (
                    octets[0].parse::<u32>(),
                    octets[1].parse::<u32>(),
                    octets[2].parse::<u32>(),
                    octets[3].parse::<u32>(),
                ) {
                    // Skip localhost and private ranges
                    if !part.starts_with("127.")
                        && !part.starts_with("192.168.")
                        && !part.starts_with("10.")
                        && !part.starts_with("172.")
                    {
                        return Some(part.to_string());
                    }
                }
            }
        }
    }

    None
}
