// linux/sensors/ebpf_primitives/mod.rs
// Linux parity primitives: cred_access, discovery, archive_tool_exec, staging_write, net_connect
// Extended: persistence_change, defense_evasion, process_injection, auth_event, script_exec

pub mod archive_tool_exec;
pub mod auth_event;
pub mod composite_detectors;
pub mod cred_access;
pub mod defense_evasion;
pub mod discovery_exec;
pub mod net_connect;
pub mod persistence_change;
pub mod process_injection;
pub mod script_exec;
pub mod staging_write;

use crate::core::Event;

/// Derive primitive events from a base event (exec, file_op, or network event)
/// Returns Vec<Event> with canonical primitive tags
pub fn derive_primitive_events(base_event: &Event) -> Vec<Event> {
    let mut derived = Vec::new();

    // Check event tags to determine what primitive detections to run
    if base_event.tags.contains(&"exec".to_string()) {
        // Try cred access detection
        if let Some(evt) = cred_access::detect_cred_access(base_event) {
            derived.push(evt);
        }

        // Try discovery exec detection
        if let Some(evt) = discovery_exec::detect_discovery_exec(base_event) {
            derived.push(evt);
        }

        // Try archive tool detection
        if let Some(evt) = archive_tool_exec::detect_archive_tool_exec(base_event) {
            derived.push(evt);
        }

        // Try persistence change from exec (crontab, systemctl, etc.)
        if let Some(evt) = persistence_change::detect_persistence_change_from_exec(base_event) {
            derived.push(evt);
        }

        // Try defense evasion from exec (history -c, shred, etc.)
        if let Some(evt) = defense_evasion::detect_defense_evasion_from_exec(base_event) {
            derived.push(evt);
        }

        // Try process injection from exec (gdb -p, strace -p, etc.)
        if let Some(evt) = process_injection::detect_process_injection_from_exec(base_event) {
            derived.push(evt);
        }

        // Try auth event from exec (su, sudo, ssh, etc.)
        if let Some(evt) = auth_event::detect_auth_event_from_exec(base_event) {
            derived.push(evt);
        }

        // Try script exec detection (bash, python, perl, etc.)
        if let Some(evt) = script_exec::detect_script_exec(base_event) {
            derived.push(evt);
        }

        // Try LOLBin detection (curl | bash, nc -e, etc.)
        if let Some(evt) = script_exec::detect_lolbin_exec(base_event) {
            derived.push(evt);
        }
    }

    // Check for file operations to derive staging write + persistence + evasion events
    if base_event.tags.contains(&"file".to_string()) {
        if let Some(evt) = staging_write::detect_staging_write(base_event) {
            derived.push(evt);
        }

        // Persistence change from file ops (modifying cron, systemd, profiles)
        if let Some(evt) = persistence_change::detect_persistence_change(base_event) {
            derived.push(evt);
        }

        // Defense evasion from file ops (log deletion, history clearing)
        if let Some(evt) = defense_evasion::detect_defense_evasion(base_event) {
            derived.push(evt);
        }

        // Process injection via /proc/*/mem writes
        if let Some(evt) = process_injection::detect_process_injection_from_file(base_event) {
            derived.push(evt);
        }
    }

    // Check for network connections to derive net_connect events
    if base_event.tags.contains(&"network".to_string()) {
        if let Some(evt) = net_connect::detect_net_connect(base_event) {
            derived.push(evt);
        }
    }

    // Check for syscall events (ptrace, process_vm_writev)
    if base_event
        .tags
        .iter()
        .any(|t| t.contains("syscall") || t.contains("ptrace"))
    {
        if let Some(evt) = process_injection::detect_process_injection_from_syscall(base_event) {
            derived.push(evt);
        }
    }

    // Check for PAM/audit auth events
    if base_event
        .tags
        .iter()
        .any(|t| t.contains("pam") || t.contains("auth") || t.contains("audit"))
    {
        if let Some(evt) = auth_event::detect_auth_event_from_audit(base_event) {
            derived.push(evt);
        }
    }

    // === HIGH-VALUE COMPOSITE DETECTORS ===
    if base_event.tags.contains(&"exec".to_string()) {
        // Detect ptrace-based injection with privilege escalation
        if let Some(evt) =
            composite_detectors::detect_ptrace_privilege_escalation_injection(base_event)
        {
            derived.push(evt);
        }

        // Detect shadow file access with credential harvesting intent
        if let Some(evt) = composite_detectors::detect_shadow_file_with_sudo_chain(base_event) {
            derived.push(evt);
        }

        // Detect log deletion evasion
        if let Some(evt) = composite_detectors::detect_log_deletion_with_sudo_escalation(base_event)
        {
            derived.push(evt);
        }

        // Detect cron persistence setup
        if let Some(evt) = composite_detectors::detect_cron_persistence_with_install(base_event) {
            derived.push(evt);
        }
    }

    derived
}
