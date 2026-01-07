// linux/sensors/ebpf_primitives/auth_event.rs
// Detects authentication events (su, sudo, ssh login, PAM events)

use crate::core::event_keys;
use crate::core::Event;
use serde_json::json;
use std::collections::BTreeMap;

/// Auth tools to detect
const AUTH_TOOLS: &[(&str, &str)] = &[
    ("su", "su"),
    ("sudo", "sudo"),
    ("ssh", "ssh"),
    ("sshd", "ssh"),
    ("login", "login"),
    ("passwd", "passwd"),
    ("chpasswd", "passwd"),
    ("newgrp", "group"),
    ("pkexec", "polkit"),
    ("doas", "doas"),
    ("ksu", "kerberos"),
    ("kinit", "kerberos"),
    ("klist", "kerberos"),
];

/// Detect auth event from exec (su, sudo, ssh, etc.)
pub fn detect_auth_event_from_exec(base_event: &Event) -> Option<Event> {
    let exe = base_event
        .fields
        .get(event_keys::PROC_EXE)
        .and_then(|v| v.as_str())?;

    let exe_base = std::path::Path::new(exe).file_name()?.to_str()?;

    // Check if exe matches auth tool
    let (_, auth_method) = AUTH_TOOLS.iter().find(|(tool, _)| exe_base == *tool)?;

    let argv = base_event
        .fields
        .get(event_keys::PROC_ARGV)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .take(20)
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    // Extract user info
    let uid = base_event
        .fields
        .get(event_keys::PROC_UID)
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)?;

    let euid = base_event
        .fields
        .get(event_keys::PROC_EUID)
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .unwrap_or(uid);

    let pid = base_event
        .fields
        .get(event_keys::PROC_PID)
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)?;

    // Determine target user if available
    let target_user = extract_target_user(&argv, exe_base);
    let auth_user = target_user.unwrap_or_else(|| format!("uid:{}", uid));

    // Auth result is "attempt" at exec time (success/fail determined later)
    let auth_result = "attempt";

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::AUTH_USER.to_string(), json!(auth_user));
    fields.insert(event_keys::AUTH_METHOD.to_string(), json!(auth_method));
    fields.insert(event_keys::AUTH_RESULT.to_string(), json!(auth_result));
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(euid));
    fields.insert(event_keys::PROC_EXE.to_string(), json!(exe));

    if !argv.is_empty() {
        fields.insert(event_keys::PROC_ARGV.to_string(), json!(argv));
    }

    Some(Event {
        ts_ms: base_event.ts_ms,
        host: base_event.host.clone(),
        tags: vec![
            "linux".to_string(),
            "auth_event".to_string(),
            "ebpf".to_string(),
        ],
        proc_key: base_event.proc_key.clone(),
        file_key: None,
        identity_key: base_event.identity_key.clone(),
        evidence_ptr: None,
        fields,
    })
}

/// Detect auth event from PAM/audit log parsing (passed as JSON fields)
pub fn detect_auth_event_from_audit(base_event: &Event) -> Option<Event> {
    // Check for PAM or audit tagged events
    if !base_event
        .tags
        .iter()
        .any(|t| t.contains("pam") || t.contains("auth") || t.contains("audit"))
    {
        return None;
    }

    // Get auth-specific fields
    let user = base_event
        .fields
        .get(event_keys::AUTH_USER)
        .or_else(|| base_event.fields.get("user"))
        .or_else(|| base_event.fields.get("acct"))
        .and_then(|v| v.as_str())?;

    let method = base_event
        .fields
        .get("service")
        .or_else(|| base_event.fields.get("pam_service"))
        .and_then(|v| v.as_str())
        .unwrap_or("pam");

    let result_raw = base_event
        .fields
        .get("res")
        .or_else(|| base_event.fields.get("result"))
        .or_else(|| base_event.fields.get("success"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let auth_result = match result_raw.to_lowercase().as_str() {
        "success" | "succeeded" | "1" | "true" => "success",
        "failed" | "failure" | "0" | "false" => "failure",
        _ => "unknown",
    };

    let pid = base_event
        .fields
        .get(event_keys::PROC_PID)
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .unwrap_or(0);

    let uid = base_event
        .fields
        .get(event_keys::PROC_UID)
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .unwrap_or(0);

    let src_ip = base_event
        .fields
        .get("addr")
        .or_else(|| base_event.fields.get("hostname"))
        .and_then(|v| v.as_str());

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::AUTH_USER.to_string(), json!(user));
    fields.insert(event_keys::AUTH_METHOD.to_string(), json!(method));
    fields.insert(event_keys::AUTH_RESULT.to_string(), json!(auth_result));

    if pid > 0 {
        fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    }
    if uid > 0 {
        fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
        fields.insert(event_keys::PROC_EUID.to_string(), json!(uid));
    }
    if let Some(ip) = src_ip {
        fields.insert(event_keys::AUTH_SRC_IP.to_string(), json!(ip));
    }

    Some(Event {
        ts_ms: base_event.ts_ms,
        host: base_event.host.clone(),
        tags: vec![
            "linux".to_string(),
            "auth_event".to_string(),
            "audit".to_string(),
        ],
        proc_key: base_event.proc_key.clone(),
        file_key: None,
        identity_key: base_event.identity_key.clone(),
        evidence_ptr: None,
        fields,
    })
}

fn extract_target_user(argv: &[&str], exe: &str) -> Option<String> {
    match exe {
        "su" => {
            // su [-] [user]
            for arg in argv.iter().take(5) {
                if !arg.starts_with('-') && *arg != "su" {
                    return Some(arg.to_string());
                }
            }
            Some("root".to_string())
        }
        "sudo" => {
            // sudo [-u user] command
            let mut found_u = false;
            for arg in argv.iter().take(10) {
                if found_u {
                    return Some(arg.to_string());
                }
                if *arg == "-u" {
                    found_u = true;
                }
            }
            Some("root".to_string())
        }
        "ssh" => {
            // ssh [user@]host
            for arg in argv.iter().take(10) {
                if arg.contains('@') {
                    return arg.split('@').next().map(|s| s.to_string());
                }
            }
            None
        }
        "login" => {
            // login [user]
            for arg in argv.iter().take(3) {
                if !arg.starts_with('-') && *arg != "login" {
                    return Some(arg.to_string());
                }
            }
            None
        }
        _ => None,
    }
}
