//! signal_integrity_mapper sensor v2
//! Cross-source inconsistencies (/proc vs ss, /proc/modules vs sysfs); emit integrity_violation

use crate::core::Event;
use crate::linux::event_builders;
use crate::linux::host::HostCtx;
use serde_json::json;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::process::Command;

/// Collect signal_integrity_mapper events - cross-source consistency checks
pub fn collect(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Check 1: High-precision invariant - /proc vs netstat/ss inconsistency
    events.extend(check_network_consistency(host));

    // Check 2: Heuristic - kernel module consistency
    events.extend(check_module_consistency(host));

    events
}

fn check_network_consistency(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Get connections from /proc/net/tcp
    let mut proc_conns = HashSet::new();
    if let Ok(content) = fs::read_to_string("/proc/net/tcp") {
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                proc_conns.insert(parts[2].to_string()); // remote address
            }
        }
    }

    // Try to get connections from ss/netstat for comparison
    if let Ok(output) = Command::new("ss").arg("-tun").output() {
        if output.status.success() {
            let ss_output = String::from_utf8_lossy(&output.stdout);

            // Count how many ss entries we find
            let ss_count = ss_output.lines().count();
            let proc_count = proc_conns.len();

            // Significant mismatch could indicate tampering
            if ss_count > 0 && proc_count > 0 {
                let ratio = (ss_count as f32 / proc_count as f32).abs();

                if ratio > 2.0 || ratio < 0.5 {
                    let key = "network_inconsistency";
                    if super::common::rate_limit("signal_integrity_mapper", key, 3600000) {
                        let mut fields = BTreeMap::new();
                        fields.insert("proc_count".to_string(), json!(proc_count));
                        fields.insert("ss_count".to_string(), json!(ss_count));
                        fields.insert("ratio".to_string(), json!(ratio));
                        fields.insert("source1".to_string(), json!("/proc/net/tcp"));
                        fields.insert("source2".to_string(), json!("ss -tun"));

                        events.push(event_builders::event(
                            host,
                            "signal_integrity_mapper",
                            "integrity_violation",
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

fn check_module_consistency(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Get modules from /proc/modules
    let mut proc_modules = HashSet::new();
    if let Ok(content) = fs::read_to_string("/proc/modules") {
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if !parts.is_empty() {
                proc_modules.insert(parts[0].to_string());
            }
        }
    }

    // Get modules from /sys/module
    let mut sysfs_modules = HashSet::new();
    if let Ok(entries) = fs::read_dir("/sys/module") {
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                sysfs_modules.insert(name);
            }
        }
    }

    // Check for discrepancies
    // Modules in /proc but not in /sys (suspicious - could indicate rootkit)
    let orphaned = proc_modules.difference(&sysfs_modules).collect::<Vec<_>>();

    if !orphaned.is_empty() {
        for module_name in orphaned {
            let key = format!("orphaned_module:{}", module_name);
            if super::common::seen_once("signal_integrity_mapper", &key) {
                let mut fields = BTreeMap::new();
                fields.insert("module_name".to_string(), json!(module_name));
                fields.insert("in_proc_modules".to_string(), json!(true));
                fields.insert("in_sysfs".to_string(), json!(false));
                fields.insert("discrepancy_type".to_string(), json!("orphaned"));

                events.push(event_builders::event(
                    host,
                    "signal_integrity_mapper",
                    "integrity_violation",
                    "critical",
                    fields,
                ));
            }
        }
    }

    // Modules in /sys but not in /proc (could indicate hidden unloading)
    let hidden = sysfs_modules.difference(&proc_modules).collect::<Vec<_>>();

    if !hidden.is_empty() && hidden.len() < 50 {
        // Limit reporting
        for module_name in hidden.iter().take(5) {
            let key = format!("hidden_module:{}", module_name);
            if super::common::rate_limit("signal_integrity_mapper", &key, 3600000) {
                let mut fields = BTreeMap::new();
                fields.insert("module_name".to_string(), json!(module_name.to_string()));
                fields.insert("in_proc_modules".to_string(), json!(false));
                fields.insert("in_sysfs".to_string(), json!(true));
                fields.insert("discrepancy_type".to_string(), json!("hidden"));

                events.push(event_builders::event(
                    host,
                    "signal_integrity_mapper",
                    "integrity_violation",
                    "medium",
                    fields,
                ));
            }
        }
    }

    events
}
