// linux/sensors/ebpf_primitives/defense_evasion.rs
// Detects defense evasion activities (log clearing, history deletion, audit tampering)

use crate::core::event_keys;
use crate::core::Event;
use serde_json::json;
use std::collections::BTreeMap;

/// Log and audit paths to monitor for tampering
const LOG_TARGETS: &[(&str, &str)] = &[
    // System logs
    ("/var/log/auth.log", "log"),
    ("/var/log/secure", "log"),
    ("/var/log/syslog", "log"),
    ("/var/log/messages", "log"),
    ("/var/log/kern.log", "log"),
    ("/var/log/daemon.log", "log"),
    ("/var/log/cron", "log"),
    ("/var/log/lastlog", "log"),
    ("/var/log/wtmp", "log"),
    ("/var/log/btmp", "log"),
    ("/var/log/utmp", "log"),
    ("/run/utmp", "log"),
    // Audit logs
    ("/var/log/audit/", "audit"),
    ("/var/log/audit.log", "audit"),
    // Shell history
    (".bash_history", "history"),
    (".zsh_history", "history"),
    (".sh_history", "history"),
    (".history", "history"),
    (".python_history", "history"),
    (".mysql_history", "history"),
    (".psql_history", "history"),
    (".lesshst", "history"),
    (".viminfo", "history"),
    // Application logs
    ("/var/log/apache2/", "log"),
    ("/var/log/nginx/", "log"),
    ("/var/log/httpd/", "log"),
];

/// Tools used for evasion
const EVASION_TOOLS: &[&str] = &[
    "shred",
    "wipe",
    "srm",
    "bleachbit",
    "unset", // unset HISTFILE
    "truncate",
];

/// Detect defense evasion from file operations
pub fn detect_defense_evasion(base_event: &Event) -> Option<Event> {
    // Must be a file event
    if !base_event.tags.iter().any(|t| t == "file") {
        return None;
    }

    let path = base_event
        .fields
        .get(event_keys::FILE_PATH)
        .and_then(|v| v.as_str())?;

    let op = base_event
        .fields
        .get(event_keys::FILE_OP)
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    // Check if path is a log/audit/history target
    let (evasion_target, evasion_action) = match_evasion_target(path, op)?;

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
    fields.insert(
        event_keys::EVASION_TARGET.to_string(),
        json!(evasion_target),
    );
    fields.insert(
        event_keys::EVASION_ACTION.to_string(),
        json!(evasion_action),
    );
    fields.insert(event_keys::FILE_PATH.to_string(), json!(path));

    Some(Event {
        ts_ms: base_event.ts_ms,
        host: base_event.host.clone(),
        tags: vec![
            "linux".to_string(),
            "defense_evasion".to_string(),
            "ebpf".to_string(),
        ],
        proc_key: base_event.proc_key.clone(),
        file_key: base_event.file_key.clone(),
        identity_key: base_event.identity_key.clone(),
        evidence_ptr: None,
        fields,
    })
}

/// Detect defense evasion from exec (history clearing, shred, etc.)
pub fn detect_defense_evasion_from_exec(base_event: &Event) -> Option<Event> {
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
                .take(20)
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let argv_joined = argv.join(" ").to_lowercase();

    // Detect evasion commands
    let (evasion_target, evasion_action) = detect_evasion_command(exe_base, &argv_joined)?;

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
    fields.insert(
        event_keys::EVASION_TARGET.to_string(),
        json!(evasion_target),
    );
    fields.insert(
        event_keys::EVASION_ACTION.to_string(),
        json!(evasion_action),
    );

    if !argv.is_empty() {
        fields.insert(event_keys::PROC_ARGV.to_string(), json!(argv));
    }

    Some(Event {
        ts_ms: base_event.ts_ms,
        host: base_event.host.clone(),
        tags: vec![
            "linux".to_string(),
            "defense_evasion".to_string(),
            "ebpf".to_string(),
        ],
        proc_key: base_event.proc_key.clone(),
        file_key: None,
        identity_key: base_event.identity_key.clone(),
        evidence_ptr: None,
        fields,
    })
}

fn match_evasion_target(path: &str, op: &str) -> Option<(&'static str, &'static str)> {
    // Only destructive operations count as evasion
    let is_destructive = matches!(
        op,
        "unlink" | "delete" | "truncate" | "remove" | "rename" | "write"
    );
    if !is_destructive && op != "chmod" {
        return None;
    }

    for (pattern, target_type) in LOG_TARGETS {
        if path.contains(pattern) {
            let action = match op {
                "unlink" | "delete" | "remove" => "delete",
                "truncate" | "write" => "truncate",
                "chmod" => "disable",
                _ => "clear",
            };
            return Some((target_type, action));
        }
    }
    None
}

fn detect_evasion_command(exe: &str, argv: &str) -> Option<(&'static str, &'static str)> {
    match exe {
        "history" if argv.contains("-c") || argv.contains("-w") => Some(("history", "clear")),
        "shred" | "srm" | "wipe" => {
            if argv.contains("var/log") || argv.contains("history") || argv.contains("audit") {
                Some(("log", "delete"))
            } else {
                None
            }
        }
        "truncate" => {
            if argv.contains("var/log") || argv.contains("history") {
                Some(("log", "truncate"))
            } else {
                None
            }
        }
        "rm" => {
            // rm -rf /var/log/* or history files
            if (argv.contains("-rf") || argv.contains("-f"))
                && (argv.contains("var/log") || argv.contains("history") || argv.contains("audit"))
            {
                Some(("log", "delete"))
            } else {
                None
            }
        }
        "auditctl" if argv.contains("-D") || argv.contains("-e 0") => Some(("audit", "disable")),
        "service" | "systemctl"
            if argv.contains("auditd") && (argv.contains("stop") || argv.contains("disable")) =>
        {
            Some(("audit", "disable"))
        }
        "setenforce" if argv.contains("0") => Some(("security_tool", "disable")),
        "iptables" if argv.contains("-F") || argv.contains("--flush") => {
            Some(("security_tool", "disable"))
        }
        "ufw" if argv.contains("disable") => Some(("security_tool", "disable")),
        "unset" if argv.contains("histfile") || argv.contains("histsize") => {
            Some(("history", "disable"))
        }
        _ => None,
    }
}
