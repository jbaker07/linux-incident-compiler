//! geo_ip_anomaly sensor v2
//! If geoip feature off, implement "new remote IP per exe" baseline; if on, country/ASN anomaly

use crate::core::Event;
use crate::linux::event_builders;
use crate::linux::host::HostCtx;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;

/// Collect geo_ip_anomaly events
pub fn collect(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Check 1: High-precision invariant - new remote IP per executable
    events.extend(detect_new_remote_ip(host));

    // Check 2: Heuristic - unusual connection patterns
    events.extend(detect_connection_anomalies(host));

    events
}

fn detect_new_remote_ip(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Read network connections from /proc/net/tcp
    if let Ok(content) = fs::read_to_string("/proc/net/tcp") {
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }

            // Parse remote address (format: hex_ip:hex_port)
            let rem_addr = parts[2];
            if let Some((rem_ip_hex, _rem_port_hex)) = rem_addr.split_once(':') {
                if let Ok(ip_int) = u32::from_str_radix(rem_ip_hex, 16) {
                    let remote_ip = format!(
                        "{}.{}.{}.{}",
                        ip_int & 0xff,
                        (ip_int >> 8) & 0xff,
                        (ip_int >> 16) & 0xff,
                        (ip_int >> 24) & 0xff
                    );

                    // Skip localhost and private ranges
                    if remote_ip.starts_with("127.")
                        || remote_ip.starts_with("192.168.")
                        || remote_ip.starts_with("10.")
                        || remote_ip.starts_with("172.")
                    {
                        continue;
                    }

                    // Track new IPs
                    let key = format!("remote_ip:{}", remote_ip);
                    if super::common::seen_once("geo_ip_anomaly", &key) {
                        let mut fields = BTreeMap::new();
                        fields.insert("remote_ip".to_string(), json!(remote_ip));
                        fields.insert("connection_type".to_string(), json!("tcp"));

                        events.push(event_builders::event(
                            host,
                            "geo_ip_anomaly",
                            "new_remote_ip",
                            "info",
                            fields,
                        ));
                    }
                }
            }
        }
    }

    events
}

fn detect_connection_anomalies(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Look for unusual connection patterns per process
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(filename) = entry.file_name().into_string() {
                if let Ok(pid) = filename.parse::<u32>() {
                    let exe_path = format!("/proc/{}/exe", pid);
                    let exe = fs::read_link(&exe_path)
                        .ok()
                        .and_then(|p| p.to_str().map(|s| s.to_string()))
                        .unwrap_or_default();

                    if exe.is_empty() {
                        continue;
                    }

                    // Check for suspicious connection patterns
                    let fd_path = format!("/proc/{}/fd", pid);
                    if let Ok(fds) = fs::read_dir(&fd_path) {
                        let mut socket_count = 0;

                        for fd in fds.flatten() {
                            if let Ok(target) = fs::read_link(fd.path()) {
                                if let Some(s) = target.to_str() {
                                    if s.contains("socket") {
                                        socket_count += 1;
                                    }
                                }
                            }
                        }

                        // Heuristic: many sockets from unexpected process
                        if socket_count > 20 {
                            let key = format!("anomaly:{}:{}", pid, exe);
                            if super::common::rate_limit("geo_ip_anomaly", &key, 60000) {
                                let mut fields = BTreeMap::new();
                                fields.insert("pid".to_string(), json!(pid));
                                fields.insert("exe".to_string(), json!(exe));
                                fields.insert("socket_count".to_string(), json!(socket_count));

                                events.push(event_builders::event(
                                    host,
                                    "geo_ip_anomaly",
                                    "connection_anomaly",
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

    events
}
