// linux/sensors/ebpf_primitives/persistence_change.rs
// Detects persistence mechanism changes (cron, systemd, shell profiles, etc.)

use crate::core::event_keys;
use crate::core::Event;
use serde_json::json;
use std::collections::BTreeMap;

/// Persistence locations to detect
const PERSISTENCE_PATHS: &[(&str, &str)] = &[
    // Shell profiles
    (".bashrc", "profile"),
    (".bash_profile", "profile"),
    (".profile", "profile"),
    (".zshrc", "profile"),
    (".zprofile", "profile"),
    ("/etc/profile", "profile"),
    ("/etc/profile.d/", "profile"),
    ("/etc/bash.bashrc", "profile"),
    // Cron
    ("/etc/cron.d/", "cron"),
    ("/etc/cron.daily/", "cron"),
    ("/etc/cron.hourly/", "cron"),
    ("/etc/cron.weekly/", "cron"),
    ("/etc/cron.monthly/", "cron"),
    ("/var/spool/cron/", "cron"),
    ("/etc/crontab", "cron"),
    // Systemd
    ("/etc/systemd/system/", "systemd"),
    ("/usr/lib/systemd/system/", "systemd"),
    ("/.config/systemd/user/", "systemd"),
    // Init
    ("/etc/init.d/", "init"),
    ("/etc/rc.local", "init"),
    ("/etc/rc.d/", "init"),
    // SSH
    (".ssh/authorized_keys", "ssh"),
    (".ssh/rc", "ssh"),
    ("/etc/ssh/sshrc", "ssh"),
    // LD_PRELOAD
    ("/etc/ld.so.preload", "ld_preload"),
    ("/etc/ld.so.conf", "ld_preload"),
    ("/etc/ld.so.conf.d/", "ld_preload"),
    // PAM
    ("/etc/pam.d/", "pam"),
    // Sudoers
    ("/etc/sudoers", "sudoers"),
    ("/etc/sudoers.d/", "sudoers"),
    // Udev rules
    ("/etc/udev/rules.d/", "udev"),
    ("/lib/udev/rules.d/", "udev"),
];

/// Detect persistence change from file operations
pub fn detect_persistence_change(base_event: &Event) -> Option<Event> {
    // Must be a file event
    if !base_event.tags.iter().any(|t| t == "file") {
        return None;
    }

    // Get file path
    let path = base_event
        .fields
        .get(event_keys::FILE_PATH)
        .and_then(|v| v.as_str())?;

    // Get file operation
    let op = base_event
        .fields
        .get(event_keys::FILE_OP)
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    // Check if path matches persistence location
    let (persist_type, action) = match_persistence_path(path, op)?;

    // Extract process info
    let pid = base_event
        .fields
        .get(event_keys::PROC_PID)
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)?;

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

    let exe = base_event
        .fields
        .get(event_keys::PROC_EXE)
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(euid));
    fields.insert(event_keys::PROC_EXE.to_string(), json!(exe));
    fields.insert(event_keys::PERSIST_LOCATION.to_string(), json!(path));
    fields.insert(event_keys::PERSIST_TYPE.to_string(), json!(persist_type));
    fields.insert(event_keys::PERSIST_ACTION.to_string(), json!(action));

    Some(Event {
        ts_ms: base_event.ts_ms,
        host: base_event.host.clone(),
        tags: vec![
            "linux".to_string(),
            "persistence_change".to_string(),
            "ebpf".to_string(),
        ],
        proc_key: base_event.proc_key.clone(),
        file_key: base_event.file_key.clone(),
        identity_key: base_event.identity_key.clone(),
        evidence_ptr: None, // Capture assigns
        fields,
    })
}

/// Detect persistence change from exec (crontab, systemctl, etc.)
pub fn detect_persistence_change_from_exec(base_event: &Event) -> Option<Event> {
    let exe = base_event
        .fields
        .get(event_keys::PROC_EXE)
        .and_then(|v| v.as_str())?;

    let exe_base = std::path::Path::new(exe).file_name()?.to_str()?;

    let argv = base_event
        .fields
        .get(event_keys::PROC_ARGV)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .take(20) // Bound argv processing
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let argv_joined = argv.join(" ").to_lowercase();

    // Detect persistence-related commands
    let (persist_type, action, location) = detect_persistence_command(exe_base, &argv_joined)?;

    // Extract process info
    let pid = base_event
        .fields
        .get(event_keys::PROC_PID)
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)?;

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

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(euid));
    fields.insert(event_keys::PROC_EXE.to_string(), json!(exe));
    fields.insert(event_keys::PERSIST_LOCATION.to_string(), json!(location));
    fields.insert(event_keys::PERSIST_TYPE.to_string(), json!(persist_type));
    fields.insert(event_keys::PERSIST_ACTION.to_string(), json!(action));

    if !argv.is_empty() {
        fields.insert(event_keys::PROC_ARGV.to_string(), json!(argv));
    }

    Some(Event {
        ts_ms: base_event.ts_ms,
        host: base_event.host.clone(),
        tags: vec![
            "linux".to_string(),
            "persistence_change".to_string(),
            "ebpf".to_string(),
        ],
        proc_key: base_event.proc_key.clone(),
        file_key: None,
        identity_key: base_event.identity_key.clone(),
        evidence_ptr: None,
        fields,
    })
}

fn match_persistence_path(path: &str, op: &str) -> Option<(&'static str, &'static str)> {
    for (pattern, persist_type) in PERSISTENCE_PATHS {
        if path.contains(pattern) {
            let action = match op {
                "write" | "create" | "open_write" => "create",
                "unlink" | "delete" | "remove" => "delete",
                "rename" | "chmod" | "chown" | "modify" => "modify",
                _ => "modify",
            };
            return Some((persist_type, action));
        }
    }
    None
}

fn detect_persistence_command(
    exe: &str,
    argv: &str,
) -> Option<(&'static str, &'static str, String)> {
    match exe {
        "crontab" => {
            let action = if argv.contains("-r") || argv.contains("--remove") {
                "delete"
            } else if argv.contains("-e") || argv.contains("-l") {
                "modify"
            } else {
                "create"
            };
            Some(("cron", action, "crontab".to_string()))
        }
        "systemctl" => {
            let action = if argv.contains("enable") {
                "create"
            } else if argv.contains("disable") {
                "delete"
            } else if argv.contains("daemon-reload")
                || argv.contains("restart")
                || argv.contains("start")
            {
                "modify"
            } else {
                return None;
            };
            // Try to extract service name (bounded)
            let service = argv
                .split_whitespace()
                .filter(|s| s.ends_with(".service") || s.ends_with(".timer"))
                .next()
                .unwrap_or("unknown");
            Some(("systemd", action, service.to_string()))
        }
        "update-rc.d" | "chkconfig" => {
            let action = if argv.contains("remove") || argv.contains("off") {
                "delete"
            } else {
                "create"
            };
            Some(("init", action, "init.d service".to_string()))
        }
        "ssh-keygen" if argv.contains("-R") => Some(("ssh", "delete", "known_hosts".to_string())),
        _ => None,
    }
}
