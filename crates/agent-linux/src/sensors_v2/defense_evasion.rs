//! Linux defense evasion detection primitives
//! Log tampering and audit tampering events

use crate::core::{event_keys, Event};
use crate::linux::event_builders;
use crate::linux::host::HostCtx;
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// Collect log tampering events from eBPF file syscall stream
/// Monitors: /var/log/, /var/tmp/, /tmp/, ~/.bash_history, ~/.zsh_history
pub fn collect_log_tamper(host: &HostCtx, ebpf_events: &[crate::core::Event]) -> Vec<Event> {
    let mut events = Vec::new();
    let log_patterns = [
        "/var/log/",
        "/var/tmp/",
        "/tmp/",
        ".bash_history",
        ".zsh_history",
    ];

    // Filter eBPF file operation events (unlink, rename, chmod, chown)
    for ebpf_evt in ebpf_events {
        if !ebpf_evt.tag_contains("file") {
            continue;
        }

        // Check for file operation types
        let op_type = match ebpf_evt
            .fields
            .get(event_keys::EVENT_KIND)
            .and_then(|v| v.as_str())
        {
            Some("unlink") => Some("unlink"),
            Some("rename") => Some("rename"),
            Some("chmod") => Some("chmod"),
            Some("chown") => Some("chown"),
            _ => None,
        };

        let op_type = match op_type {
            Some(op) => op,
            None => continue,
        };

        let path = match ebpf_evt
            .fields
            .get(event_keys::FILE_PATH)
            .and_then(|v| v.as_str())
        {
            Some(p) => p,
            None => continue,
        };

        // Check if path matches log patterns
        let is_log_target = log_patterns.iter().any(|pat| path.contains(pat));
        if !is_log_target {
            continue;
        }

        let pid = ebpf_evt
            .fields
            .get(event_keys::PROC_PID)
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        let uid = ebpf_evt
            .fields
            .get(event_keys::PROC_UID)
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        let exe = ebpf_evt
            .fields
            .get(event_keys::PROC_EXE)
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let mut fields = BTreeMap::new();
        fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
        fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
        fields.insert(event_keys::PROC_EXE.to_string(), json!(exe));
        fields.insert(event_keys::FILE_PATH.to_string(), json!(path));
        fields.insert("op".to_string(), json!(op_type));

        if op_type == "chmod" {
            if let Some(mode) = ebpf_evt.fields.get("mode").and_then(|v| v.as_u64()) {
                fields.insert("mode".to_string(), json!(mode));
            }
        }

        let mut ev = event_builders::event(host, "attack_surface", "log_tamper", "high", fields);
        ev.tags.extend(vec![
            "defense_evasion".to_string(),
            "log_tamper".to_string(),
        ]);
        events.push(ev);
    }

    events
}

/// Collect audit tampering events from eBPF file syscall stream
/// Monitors: /etc/audit/, /var/log/audit/, /etc/rsyslog*
pub fn collect_audit_tamper(host: &HostCtx, ebpf_events: &[crate::core::Event]) -> Vec<Event> {
    let mut events = Vec::new();
    let audit_patterns = ["/etc/audit/", "/var/log/audit/", "/etc/rsyslog"];

    // Filter eBPF file operation events
    for ebpf_evt in ebpf_events {
        if !ebpf_evt.tag_contains("file") {
            continue;
        }

        let op_type = match ebpf_evt
            .fields
            .get(event_keys::EVENT_KIND)
            .and_then(|v| v.as_str())
        {
            Some("unlink") => Some("unlink"),
            Some("rename") => Some("rename"),
            Some("chmod") => Some("chmod"),
            Some("chown") => Some("chown"),
            _ => None,
        };

        let op_type = match op_type {
            Some(op) => op,
            None => continue,
        };

        let path = match ebpf_evt
            .fields
            .get(event_keys::FILE_PATH)
            .and_then(|v| v.as_str())
        {
            Some(p) => p,
            None => continue,
        };

        // Check if path matches audit patterns
        let is_audit_target = audit_patterns.iter().any(|pat| path.contains(pat));
        if !is_audit_target {
            continue;
        }

        let pid = ebpf_evt
            .fields
            .get(event_keys::PROC_PID)
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        let uid = ebpf_evt
            .fields
            .get(event_keys::PROC_UID)
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        let exe = ebpf_evt
            .fields
            .get(event_keys::PROC_EXE)
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let mut fields = BTreeMap::new();
        fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
        fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
        fields.insert(event_keys::PROC_EXE.to_string(), json!(exe));
        fields.insert(event_keys::FILE_PATH.to_string(), json!(path));
        fields.insert("op".to_string(), json!(op_type));

        let mut ev = event_builders::event(host, "attack_surface", "audit_tamper", "high", fields);
        ev.tags.extend(vec![
            "defense_evasion".to_string(),
            "audit_tamper".to_string(),
        ]);
        events.push(ev);
    }

    events
}
