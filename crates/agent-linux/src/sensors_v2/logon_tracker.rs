//! logon_tracker sensor v2
//! utmp/wtmp session deltas or who parsing fallback

use crate::core::Event;
use crate::linux::event_builders;
use crate::linux::host::HostCtx;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::process::Command;

/// Collect logon_tracker events - track user login sessions
pub fn collect(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Check 1: High-precision invariant - parse utmp/wtmp for logins
    events.extend(detect_utmp_logins(host));

    // Check 2: Heuristic - detect unusual login patterns
    events.extend(detect_unusual_logins(host));

    events
}

fn detect_utmp_logins(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Try to read utmp via `who` command (fallback approach)
    if let Ok(output) = Command::new("who").output() {
        if output.status.success() {
            let who_output = String::from_utf8_lossy(&output.stdout);

            for line in who_output.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 2 {
                    continue;
                }

                let username = parts[0];
                let tty = parts.get(1).unwrap_or(&"unknown");
                let login_time = parts.get(2..5).map(|p| p.join(" ")).unwrap_or_default();

                // Track each login session
                let key = format!("session:{}:{}", username, tty);
                if super::common::seen_once("logon_tracker", &key) {
                    let mut fields = BTreeMap::new();
                    fields.insert("username".to_string(), json!(username));
                    fields.insert("tty".to_string(), json!(tty.to_string()));
                    if !login_time.is_empty() {
                        fields.insert("login_time".to_string(), json!(login_time));
                    }

                    events.push(event_builders::event(
                        host,
                        "logon_tracker",
                        "login_session",
                        "info",
                        fields,
                    ));
                }
            }
        }
    }

    events
}

fn detect_unusual_logins(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Check for unusual system user logins
    let system_users = vec!["root", "bin", "sys", "daemon", "adm", "lp", "mail"];

    if let Ok(output) = Command::new("who").output() {
        if output.status.success() {
            let who_output = String::from_utf8_lossy(&output.stdout);

            for line in who_output.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.is_empty() {
                    continue;
                }

                let username = parts[0];

                // Check if a system user is logged in (unusual)
                if system_users.contains(&username) {
                    let key = format!("system_login:{}", username);
                    if super::common::rate_limit("logon_tracker", &key, 3600000) {
                        let mut fields = BTreeMap::new();
                        fields.insert("username".to_string(), json!(username));
                        fields.insert("is_system_user".to_string(), json!(true));

                        events.push(event_builders::event(
                            host,
                            "logon_tracker",
                            "system_user_login",
                            "medium",
                            fields,
                        ));
                    }
                }
            }
        }
    }

    // Check lastlog for unusual IPs or times
    if let Ok(_) = fs::metadata("/var/log/lastlog") {
        // In production, would parse binary lastlog format
        // For now, attempt to read with lastlog command
        if let Ok(output) = Command::new("lastlog").arg("-t").arg("1").output() {
            if output.status.success() {
                let lastlog_output = String::from_utf8_lossy(&output.stdout);

                for line in lastlog_output.lines().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        let username = parts[0];
                        let remote_host = parts.get(2..4).map(|p| p.join(" ")).unwrap_or_default();

                        // Track new remote hosts per user
                        let key = format!("remote:{}:{}", username, remote_host);
                        if super::common::seen_once("logon_tracker", &key) {
                            let mut fields = BTreeMap::new();
                            fields.insert("username".to_string(), json!(username));
                            fields.insert("remote_host".to_string(), json!(remote_host));

                            events.push(event_builders::event(
                                host,
                                "logon_tracker",
                                "remote_login",
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
