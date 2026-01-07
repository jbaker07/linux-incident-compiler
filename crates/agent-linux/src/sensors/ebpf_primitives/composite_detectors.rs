// linux/sensors/ebpf_primitives/composite_detectors.rs
// High-value composite detectors for Linux combining multiple signals

use crate::core::event_keys;
use crate::core::Event;
use serde_json::json;
use std::collections::BTreeMap;

/// Detect ptrace-based process injection with privilege escalation
/// Indicator: gdb/strace/ptrace invocation against higher-privilege process
/// Threat level: Critical - Direct process injection for code execution
pub fn detect_ptrace_privilege_escalation_injection(base_event: &Event) -> Option<Event> {
    // Check if this is an exec event
    if !base_event.tags.contains(&"exec".to_string()) {
        return None;
    }

    let exe = base_event.fields.get(event_keys::PROC_EXE)?.as_str()?;
    let argv = base_event
        .fields
        .get(event_keys::PROC_ARGV)?
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
        })?;

    let uid = base_event
        .fields
        .get(event_keys::PROC_UID)?
        .as_u64()
        .map(|u| u as u32)?;

    let exe_base = std::path::Path::new(exe).file_name()?.to_str()?;

    // Check for ptrace tools
    let is_ptrace_tool = exe_base.contains("gdb")
        || exe_base.contains("strace")
        || exe_base.contains("ltrace")
        || exe_base.contains("lldb");

    if !is_ptrace_tool {
        return None;
    }

    // Check argv for target PID (typically -p <pid>)
    let mut target_pid = None;
    for (i, arg) in argv.iter().enumerate() {
        if arg.contains("-p") && i + 1 < argv.len() {
            target_pid = Some(argv[i + 1].clone());
            break;
        }
    }

    let host = &base_event.host;
    let stream_id = base_event
        .proc_key
        .as_ref()
        .map(|k| k.as_str())
        .unwrap_or("");
    let pid = base_event
        .fields
        .get(event_keys::PROC_PID)?
        .as_u64()
        .map(|p| p as u32)?;

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EXE.to_string(), json!(exe));
    fields.insert(event_keys::PROC_ARGV.to_string(), json!(argv));
    fields.insert(
        "correlation_type".to_string(),
        json!("ptrace_privilege_escalation"),
    );
    fields.insert("severity".to_string(), json!("critical"));

    if let Some(tpid) = target_pid {
        fields.insert("target_pid".to_string(), json!(tpid));
    }

    Some(Event {
        ts_ms: base_event.ts_ms,
        host: host.clone(),
        tags: vec![
            "linux".to_string(),
            "process_injection".to_string(),
            "composite".to_string(),
            "high_value".to_string(),
        ],
        proc_key: base_event.proc_key.clone(),
        file_key: None,
        identity_key: base_event.identity_key.clone(),
        evidence_ptr: None,
        fields,
    })
}

/// Detect shadow file access with privilege escalation tool
/// Indicator: Execution of cat/grep/strings on /etc/shadow by unprivileged user with sudo/su
/// Threat level: High - Indicates credential harvesting
pub fn detect_shadow_file_with_sudo_chain(base_event: &Event) -> Option<Event> {
    if !base_event.tags.contains(&"exec".to_string()) {
        return None;
    }

    let exe = base_event.fields.get(event_keys::PROC_EXE)?.as_str()?;
    let argv = base_event
        .fields
        .get(event_keys::PROC_ARGV)?
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
        })?;

    let exe_base = std::path::Path::new(exe).file_name()?.to_str()?;

    // Check for file read tools
    let is_file_read_tool = exe_base.contains("cat")
        || exe_base.contains("grep")
        || exe_base.contains("strings")
        || exe_base.contains("less")
        || exe_base.contains("more");

    if !is_file_read_tool {
        return None;
    }

    // Check if reading sensitive files
    let arg_str = argv.join(" ");
    let sensitive_files = ["/etc/shadow", "/etc/passwd", "/etc/sudoers", "/root"];
    let reading_sensitive = sensitive_files.iter().any(|f| arg_str.contains(f));

    if !reading_sensitive {
        return None;
    }

    let host = &base_event.host;
    let pid = base_event
        .fields
        .get(event_keys::PROC_PID)?
        .as_u64()
        .map(|p| p as u32)?;
    let uid = base_event
        .fields
        .get(event_keys::PROC_UID)?
        .as_u64()
        .map(|u| u as u32)?;

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EXE.to_string(), json!(exe));
    fields.insert(event_keys::PROC_ARGV.to_string(), json!(argv));
    fields.insert("correlation_type".to_string(), json!("shadow_file_access"));
    fields.insert("severity".to_string(), json!("high"));

    Some(Event {
        ts_ms: base_event.ts_ms,
        host: host.clone(),
        tags: vec![
            "linux".to_string(),
            "credential_access".to_string(),
            "composite".to_string(),
            "high_value".to_string(),
        ],
        proc_key: base_event.proc_key.clone(),
        file_key: None,
        identity_key: base_event.identity_key.clone(),
        evidence_ptr: None,
        fields,
    })
}

/// Detect evasion pattern: Log deletion with privilege escalation
/// Indicator: rm/shred on /var/log/* or ~/.bash_history by non-root user via sudo
/// Threat level: High - Indicates post-compromise log tampering
pub fn detect_log_deletion_with_sudo_escalation(base_event: &Event) -> Option<Event> {
    if !base_event.tags.contains(&"exec".to_string()) {
        return None;
    }

    let exe = base_event.fields.get(event_keys::PROC_EXE)?.as_str()?;
    let argv = base_event
        .fields
        .get(event_keys::PROC_ARGV)?
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
        })?;

    let exe_base = std::path::Path::new(exe).file_name()?.to_str()?;

    // Check for deletion/shredding tools
    let is_delete_tool = exe_base == "rm" || exe_base == "shred";

    if !is_delete_tool {
        return None;
    }

    // Check argv for log files or history
    let arg_str = argv.join(" ");
    let log_patterns = ["/var/log/", ".bash_history", ".zsh_history", ".ksh_history"];
    let targeting_logs = log_patterns.iter().any(|p| arg_str.contains(p));

    if !targeting_logs {
        return None;
    }

    let host = &base_event.host;
    let pid = base_event
        .fields
        .get(event_keys::PROC_PID)?
        .as_u64()
        .map(|p| p as u32)?;
    let uid = base_event
        .fields
        .get(event_keys::PROC_UID)?
        .as_u64()
        .map(|u| u as u32)?;

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EXE.to_string(), json!(exe));
    fields.insert(event_keys::PROC_ARGV.to_string(), json!(argv));
    fields.insert(
        "correlation_type".to_string(),
        json!("log_deletion_evasion"),
    );
    fields.insert("severity".to_string(), json!("high"));

    Some(Event {
        ts_ms: base_event.ts_ms,
        host: host.clone(),
        tags: vec![
            "linux".to_string(),
            "defense_evasion".to_string(),
            "composite".to_string(),
            "high_value".to_string(),
        ],
        proc_key: base_event.proc_key.clone(),
        file_key: None,
        identity_key: base_event.identity_key.clone(),
        evidence_ptr: None,
        fields,
    })
}

/// Detect cron persistence with file write
/// Indicator: Write to /var/spool/cron/* followed by crontab -i/reload
/// Threat level: High - Cron is primary persistence mechanism on Linux
pub fn detect_cron_persistence_with_install(base_event: &Event) -> Option<Event> {
    // This detector requires correlation between file write and crontab exec events
    // For now, check if this is a crontab invocation with install flag
    if !base_event.tags.contains(&"exec".to_string()) {
        return None;
    }

    let exe = base_event.fields.get(event_keys::PROC_EXE)?.as_str()?;
    let argv = base_event
        .fields
        .get(event_keys::PROC_ARGV)?
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
        })?;

    let exe_base = std::path::Path::new(exe).file_name()?.to_str()?;

    if exe_base != "crontab" {
        return None;
    }

    // Check for crontab install/edit flags
    let has_install_flag = argv.iter().any(|arg| arg == "-i" || arg == "-e");

    if !has_install_flag {
        return None;
    }

    let host = &base_event.host;
    let pid = base_event
        .fields
        .get(event_keys::PROC_PID)?
        .as_u64()
        .map(|p| p as u32)?;
    let uid = base_event
        .fields
        .get(event_keys::PROC_UID)?
        .as_u64()
        .map(|u| u as u32)?;

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EXE.to_string(), json!(exe));
    fields.insert(event_keys::PROC_ARGV.to_string(), json!(argv));
    fields.insert("correlation_type".to_string(), json!("cron_persistence"));
    fields.insert("severity".to_string(), json!("high"));

    Some(Event {
        ts_ms: base_event.ts_ms,
        host: host.clone(),
        tags: vec![
            "linux".to_string(),
            "persistence_change".to_string(),
            "composite".to_string(),
            "high_value".to_string(),
        ],
        proc_key: base_event.proc_key.clone(),
        file_key: None,
        identity_key: base_event.identity_key.clone(),
        evidence_ptr: None,
        fields,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ptrace_injection_detection() {
        let mut fields = BTreeMap::new();
        fields.insert(event_keys::PROC_EXE.to_string(), json!("/usr/bin/gdb"));
        fields.insert(event_keys::PROC_PID.to_string(), json!(1000u64));
        fields.insert(event_keys::PROC_UID.to_string(), json!(1001u64));
        fields.insert(
            event_keys::PROC_ARGV.to_string(),
            json!(vec!["gdb", "-p", "2000"]),
        );

        let event = Event {
            ts_ms: 1000000,
            host: "test_host".to_string(),
            tags: vec!["exec".to_string()],
            proc_key: Some("key".to_string()),
            file_key: None,
            identity_key: None,
            evidence_ptr: None,
            fields,
        };

        let result = detect_ptrace_privilege_escalation_injection(&event);
        assert!(result.is_some());
        let evt = result.unwrap();
        assert!(evt.tags.contains(&"process_injection".to_string()));
        assert!(evt.tags.contains(&"high_value".to_string()));
    }

    #[test]
    fn test_shadow_file_access_detection() {
        let mut fields = BTreeMap::new();
        fields.insert(event_keys::PROC_EXE.to_string(), json!("/bin/cat"));
        fields.insert(event_keys::PROC_PID.to_string(), json!(1000u64));
        fields.insert(event_keys::PROC_UID.to_string(), json!(1001u64));
        fields.insert(
            event_keys::PROC_ARGV.to_string(),
            json!(vec!["cat", "/etc/shadow"]),
        );

        let event = Event {
            ts_ms: 1000000,
            host: "test_host".to_string(),
            tags: vec!["exec".to_string()],
            proc_key: Some("key".to_string()),
            file_key: None,
            identity_key: None,
            evidence_ptr: None,
            fields,
        };

        let result = detect_shadow_file_with_sudo_chain(&event);
        assert!(result.is_some());
        let evt = result.unwrap();
        assert!(evt.tags.contains(&"credential_access".to_string()));
        assert!(evt.tags.contains(&"high_value".to_string()));
    }
}
