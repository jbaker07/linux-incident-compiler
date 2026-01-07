// linux/sensors/ebpf_primitives/process_injection.rs
// Detects process injection via ptrace, /proc/*/mem, process_vm_writev, memfd_create

use crate::core::event_keys;
use crate::core::Event;
use serde_json::json;
use std::collections::BTreeMap;

/// Injection detection methods
const INJECTION_SYSCALLS: &[&str] = &["ptrace", "process_vm_writev", "memfd_create"];

/// Tools known for injection
const INJECTION_TOOLS: &[&str] = &[
    "gdb",
    "strace",
    "ltrace",
    "inject",
    "linux-inject",
    "cymothoa",
    "mandibule",
];

/// Detect process injection from exec (gdb, strace attach, etc.)
pub fn detect_process_injection_from_exec(base_event: &Event) -> Option<Event> {
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

    // Detect injection commands
    let (inject_method, target_pid) = detect_injection_command(exe_base, &argv_joined, &argv)?;

    // Extract source process info
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
    fields.insert(event_keys::INJECT_METHOD.to_string(), json!(inject_method));
    fields.insert(event_keys::INJECT_TARGET_PID.to_string(), json!(target_pid));

    if !argv.is_empty() {
        fields.insert(event_keys::PROC_ARGV.to_string(), json!(argv));
    }

    Some(Event {
        ts_ms: base_event.ts_ms,
        host: base_event.host.clone(),
        tags: vec![
            "linux".to_string(),
            "process_injection".to_string(),
            "ebpf".to_string(),
        ],
        proc_key: base_event.proc_key.clone(),
        file_key: None,
        identity_key: base_event.identity_key.clone(),
        evidence_ptr: None,
        fields,
    })
}

/// Detect injection from syscall events (ptrace, process_vm_writev)
pub fn detect_process_injection_from_syscall(base_event: &Event) -> Option<Event> {
    // Check for syscall-tagged events
    if !base_event
        .tags
        .iter()
        .any(|t| t.contains("syscall") || t.contains("ptrace"))
    {
        return None;
    }

    let syscall = base_event
        .fields
        .get("syscall")
        .or_else(|| base_event.fields.get(event_keys::EVENT_KIND))
        .and_then(|v| v.as_str())?;

    // Only injection-related syscalls
    if !INJECTION_SYSCALLS.iter().any(|s| syscall.contains(s)) {
        return None;
    }

    let inject_method = match syscall {
        s if s.contains("ptrace") => "ptrace",
        s if s.contains("process_vm_writev") => "process_vm_writev",
        s if s.contains("memfd_create") => "memfd_exec",
        _ => return None,
    };

    // Extract target PID if available
    let target_pid = base_event
        .fields
        .get("target_pid")
        .or_else(|| base_event.fields.get("arg1"))
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .map(|v| v as u32)
        .unwrap_or(0);

    // Source process info
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
    fields.insert(event_keys::INJECT_METHOD.to_string(), json!(inject_method));
    fields.insert(event_keys::INJECT_TARGET_PID.to_string(), json!(target_pid));

    Some(Event {
        ts_ms: base_event.ts_ms,
        host: base_event.host.clone(),
        tags: vec![
            "linux".to_string(),
            "process_injection".to_string(),
            "ebpf".to_string(),
        ],
        proc_key: base_event.proc_key.clone(),
        file_key: None,
        identity_key: base_event.identity_key.clone(),
        evidence_ptr: None,
        fields,
    })
}

/// Detect injection from /proc/*/mem file access
pub fn detect_process_injection_from_file(base_event: &Event) -> Option<Event> {
    if !base_event.tags.iter().any(|t| t == "file") {
        return None;
    }

    let path = base_event
        .fields
        .get(event_keys::FILE_PATH)
        .and_then(|v| v.as_str())?;

    // Pattern: /proc/<pid>/mem
    if !path.starts_with("/proc/") || !path.ends_with("/mem") {
        return None;
    }

    let op = base_event
        .fields
        .get(event_keys::FILE_OP)
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    // Only writes to /proc/<pid>/mem are injection
    if op != "write" && op != "open_write" {
        return None;
    }

    // Extract target PID from path
    let target_pid: u32 = path
        .strip_prefix("/proc/")?
        .split('/')
        .next()?
        .parse()
        .ok()?;

    // Source process info
    let pid = base_event
        .fields
        .get(event_keys::PROC_PID)
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)?;

    // Skip self-injection
    if pid == target_pid {
        return None;
    }

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
        event_keys::INJECT_METHOD.to_string(),
        json!("proc_mem_write"),
    );
    fields.insert(event_keys::INJECT_TARGET_PID.to_string(), json!(target_pid));

    Some(Event {
        ts_ms: base_event.ts_ms,
        host: base_event.host.clone(),
        tags: vec![
            "linux".to_string(),
            "process_injection".to_string(),
            "ebpf".to_string(),
        ],
        proc_key: base_event.proc_key.clone(),
        file_key: base_event.file_key.clone(),
        identity_key: base_event.identity_key.clone(),
        evidence_ptr: None,
        fields,
    })
}

fn detect_injection_command(
    exe: &str,
    argv: &str,
    argv_vec: &[&str],
) -> Option<(&'static str, u32)> {
    match exe {
        "gdb" | "lldb" => {
            // gdb -p <pid> or gdb --pid=<pid>
            if argv.contains("-p ") || argv.contains("--pid") || argv.contains("attach") {
                let target_pid = extract_pid_from_argv(argv_vec).unwrap_or(0);
                return Some(("ptrace", target_pid));
            }
            None
        }
        "strace" | "ltrace" => {
            // strace -p <pid>
            if argv.contains("-p ") {
                let target_pid = extract_pid_from_argv(argv_vec).unwrap_or(0);
                return Some(("ptrace", target_pid));
            }
            None
        }
        "inject" | "linux-inject" => {
            let target_pid = extract_pid_from_argv(argv_vec).unwrap_or(0);
            Some(("ld_preload", target_pid))
        }
        "dd" if argv.contains("/proc/") && argv.contains("/mem") => {
            let target_pid = extract_pid_from_path(argv).unwrap_or(0);
            Some(("proc_mem_write", target_pid))
        }
        _ => {
            // Check for known injection tools
            if INJECTION_TOOLS.iter().any(|t| exe.contains(t)) {
                let target_pid = extract_pid_from_argv(argv_vec).unwrap_or(0);
                return Some(("unknown", target_pid));
            }
            None
        }
    }
}

fn extract_pid_from_argv(argv: &[&str]) -> Option<u32> {
    // Look for -p <pid> pattern
    let mut found_p = false;
    for arg in argv.iter().take(10) {
        if found_p {
            if let Ok(pid) = arg.parse() {
                return Some(pid);
            }
        }
        if *arg == "-p" || *arg == "--pid" {
            found_p = true;
        } else if arg.starts_with("--pid=") {
            return arg.strip_prefix("--pid=")?.parse().ok();
        }
    }
    None
}

fn extract_pid_from_path(s: &str) -> Option<u32> {
    // Extract from /proc/<pid>/mem pattern
    if let Some(start) = s.find("/proc/") {
        let rest = &s[start + 6..];
        if let Some(end) = rest.find('/') {
            return rest[..end].parse().ok();
        }
    }
    None
}
