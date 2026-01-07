// linux/sensors/ebpf_primitives/script_exec.rs
// Detects script/interpreter execution (bash, python, perl, etc.)

use crate::core::event_keys;
use crate::core::Event;
use serde_json::json;
use std::collections::BTreeMap;

/// Script interpreters to detect
const SCRIPT_INTERPRETERS: &[(&str, &str)] = &[
    ("bash", "bash"),
    ("sh", "sh"),
    ("dash", "dash"),
    ("zsh", "zsh"),
    ("fish", "fish"),
    ("ksh", "ksh"),
    ("csh", "csh"),
    ("tcsh", "tcsh"),
    ("python", "python"),
    ("python2", "python"),
    ("python3", "python"),
    ("perl", "perl"),
    ("ruby", "ruby"),
    ("php", "php"),
    ("node", "node"),
    ("nodejs", "node"),
    ("lua", "lua"),
    ("awk", "awk"),
    ("gawk", "gawk"),
    ("nawk", "nawk"),
    ("sed", "sed"),
];

/// LOLBins (Living Off the Land Binaries)
const LOLBINS: &[&str] = &[
    "curl", "wget", "nc", "ncat", "netcat", "socat", "openssl", "nmap", "telnet", "ftp", "scp",
    "rsync", "base64", "xxd", "xargs", "find", "xdg-open", "xclip",
];

/// Detect script execution from exec events
pub fn detect_script_exec(base_event: &Event) -> Option<Event> {
    let exe = base_event
        .fields
        .get(event_keys::PROC_EXE)
        .and_then(|v| v.as_str())?;

    let exe_base = std::path::Path::new(exe).file_name()?.to_str()?;

    // Check if exe matches script interpreter
    let (_, interpreter) = SCRIPT_INTERPRETERS
        .iter()
        .find(|(tool, _)| exe_base == *tool)?;

    let argv = base_event
        .fields
        .get(event_keys::PROC_ARGV)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .take(30)
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let argv_joined = argv.join(" ");

    // Determine if inline script (-c, -e) or script file
    let (is_inline, script_path) = detect_script_mode(&argv, exe_base);

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
        event_keys::SCRIPT_INTERPRETER.to_string(),
        json!(interpreter),
    );
    fields.insert(event_keys::SCRIPT_INLINE.to_string(), json!(is_inline));

    if let Some(path) = script_path {
        fields.insert(event_keys::SCRIPT_PATH.to_string(), json!(path));
    }

    if !argv.is_empty() {
        fields.insert(event_keys::PROC_ARGV.to_string(), json!(argv));
    }

    Some(Event {
        ts_ms: base_event.ts_ms,
        host: base_event.host.clone(),
        tags: vec![
            "linux".to_string(),
            "script_exec".to_string(),
            "ebpf".to_string(),
        ],
        proc_key: base_event.proc_key.clone(),
        file_key: None,
        identity_key: base_event.identity_key.clone(),
        evidence_ptr: None,
        fields,
    })
}

/// Detect LOLBin execution with suspicious arguments
pub fn detect_lolbin_exec(base_event: &Event) -> Option<Event> {
    let exe = base_event
        .fields
        .get(event_keys::PROC_EXE)
        .and_then(|v| v.as_str())?;

    let exe_base = std::path::Path::new(exe).file_name()?.to_str()?;

    // Check if exe is a LOLBin
    if !LOLBINS.iter().any(|l| exe_base == *l) {
        return None;
    }

    let argv = base_event
        .fields
        .get(event_keys::PROC_ARGV)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .take(30)
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let argv_joined = argv.join(" ").to_lowercase();

    // Only flag suspicious LOLBin usage
    if !is_suspicious_lolbin(exe_base, &argv_joined) {
        return None;
    }

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
        event_keys::SCRIPT_INTERPRETER.to_string(),
        json!(format!("lolbin:{}", exe_base)),
    );
    fields.insert(event_keys::SCRIPT_INLINE.to_string(), json!(true));

    if !argv.is_empty() {
        fields.insert(event_keys::PROC_ARGV.to_string(), json!(argv));
    }

    Some(Event {
        ts_ms: base_event.ts_ms,
        host: base_event.host.clone(),
        tags: vec![
            "linux".to_string(),
            "script_exec".to_string(),
            "lolbin".to_string(),
        ],
        proc_key: base_event.proc_key.clone(),
        file_key: None,
        identity_key: base_event.identity_key.clone(),
        evidence_ptr: None,
        fields,
    })
}

fn detect_script_mode(argv: &[&str], _exe: &str) -> (bool, Option<String>) {
    let mut is_inline = false;
    let mut script_path = None;

    for (i, arg) in argv.iter().enumerate().take(10) {
        // -c for shells, -e for perl/ruby
        if *arg == "-c" || *arg == "-e" || *arg == "--eval" {
            is_inline = true;
        }
        // Look for script file path (ends in .sh, .py, .pl, .rb, etc.)
        else if arg.ends_with(".sh")
            || arg.ends_with(".py")
            || arg.ends_with(".pl")
            || arg.ends_with(".rb")
            || arg.ends_with(".lua")
            || arg.ends_with(".php")
        {
            if i > 0 && !arg.starts_with('-') {
                script_path = Some(arg.to_string());
            }
        }
        // File path starting with /
        else if arg.starts_with('/') && i > 0 && !arg.starts_with('-') {
            script_path = Some(arg.to_string());
        }
    }

    (is_inline, script_path)
}

fn is_suspicious_lolbin(exe: &str, argv: &str) -> bool {
    match exe {
        "curl" | "wget" => {
            // Download and execute patterns
            argv.contains("|")
                || argv.contains(">")
                || argv.contains("/dev/tcp")
                || argv.contains("bash")
                || argv.contains("-o /tmp")
                || argv.contains("-o /var/tmp")
                || argv.contains("base64")
                || argv.contains("eval")
        }
        "nc" | "ncat" | "netcat" => {
            // Reverse shell patterns
            argv.contains("-e")
                || argv.contains("-c")
                || argv.contains("/bin/sh")
                || argv.contains("/bin/bash")
        }
        "openssl" => {
            // SSL tunneling
            argv.contains("s_client") && argv.contains("connect")
        }
        "base64" => {
            // Decode and execute
            argv.contains("-d") && (argv.contains("|") || argv.contains(">"))
        }
        "find" => {
            // Find with exec
            argv.contains("-exec") && (argv.contains("sh") || argv.contains("bash"))
        }
        "xargs" => {
            // xargs command execution
            argv.contains("sh") || argv.contains("bash") || argv.contains("-I")
        }
        _ => false,
    }
}
