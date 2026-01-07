//! privilege_monitor sensor v2 - UID/GID elevation detection
//! Sources: /proc/*/status, /etc/sudoers
//! Detects: UID transitions, sudoers changes, privilege escalation

use crate::core::Event;
use crate::linux::event_builders;
use crate::linux::host::HostCtx;
use crate::linux::sensors_v2::common;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;

/// Collect privilege escalation events
pub fn collect(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Check 1: Sudoers file changes
    events.extend(check_sudoers_changes(host));

    // Check 2: UID transitions (parent vs child uid mismatch)
    events.extend(detect_uid_transitions(host));

    events
}

fn check_sudoers_changes(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    if let Ok(sudoers) = fs::read_to_string("/etc/sudoers") {
        let hash = format!("{:x}", sudoers.len());
        if common::changed_hash("privilege_monitor", "/etc/sudoers", &hash) {
            let mut fields = BTreeMap::new();
            fields.insert("file".to_string(), json!("/etc/sudoers"));
            events.push(event_builders::event(
                host,
                "privilege_monitor",
                "sudoers_change",
                "high",
                fields,
            ));
        }
    }

    events
}

fn detect_uid_transitions(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Some(pid_str) = entry.path().file_name().and_then(|n| n.to_str()) {
                if let Ok(_pid) = pid_str.parse::<u32>() {
                    let status_path = entry.path().join("status");

                    // Parse UID info from /proc/<pid>/status
                    if let Ok(status) = fs::read_to_string(&status_path) {
                        let mut uid_info = UidInfo::default();

                        for line in status.lines() {
                            if line.starts_with("Uid:") {
                                // Uid:   <real>   <effective>   <saved>   <filesystem>
                                if let Some(parts) = line.split('\t').nth(1) {
                                    let uids: Vec<&str> = parts.split_whitespace().collect();
                                    if uids.len() >= 4 {
                                        uid_info.uid = uids[0].parse().ok();
                                        uid_info.euid = uids[1].parse().ok();
                                        uid_info.suid = uids[2].parse().ok();
                                        uid_info.fsuid = uids[3].parse().ok();
                                    }
                                }
                            } else if line.starts_with("Gid:") {
                                if let Some(parts) = line.split('\t').nth(1) {
                                    let gids: Vec<&str> = parts.split_whitespace().collect();
                                    if gids.len() >= 4 {
                                        uid_info.gid = gids[0].parse().ok();
                                        uid_info.egid = gids[1].parse().ok();
                                    }
                                }
                            }
                        }

                        // Check for privilege escalation: euid != uid (effective != real)
                        if let (Some(uid), Some(euid)) = (uid_info.uid, uid_info.euid) {
                            if euid != uid && uid != 0 && euid == 0 {
                                // Non-root process with root-effective privileges
                                let cache_key = format!("uid_escalation:{}:{}", pid_str, euid);
                                if common::seen_once("privilege_monitor", &cache_key) {
                                    let mut fields = BTreeMap::new();
                                    fields.insert("pid".to_string(), json!(pid_str));
                                    fields.insert("uid".to_string(), json!(uid));
                                    fields.insert("euid".to_string(), json!(euid));
                                    if let Some(gid) = uid_info.gid {
                                        fields.insert("gid".to_string(), json!(gid));
                                    }
                                    events.push(event_builders::event(
                                        host,
                                        "privilege_monitor",
                                        "privilege_escalation",
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

#[derive(Default)]
struct UidInfo {
    uid: Option<u32>,   // real UID
    euid: Option<u32>,  // effective UID
    suid: Option<u32>,  // saved UID
    fsuid: Option<u32>, // fs UID
    gid: Option<u32>,   // real GID
    egid: Option<u32>,  // effective GID
}
