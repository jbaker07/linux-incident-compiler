//! Linux attack surface detection primitives
//! Privilege escalation, lateral movement, defense evasion, C2 signals
//! All emitted events have evidence_ptr: None (capture assigns it)

use crate::core::{event_keys, Event};
use crate::linux::event_builders;
use crate::linux::host::HostCtx;
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// Collect privilege escalation events
/// - priv_uid_change: setuid/setreuid/setresuid
/// - priv_gid_change: setgid/setregid/setresgid
/// - priv_cap_change: capset syscall
/// - priv_boundary_cross: exec with uid != euid or suid/caps elevated
pub fn collect_priv_escalation(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Read from /proc/*/syscall or /proc/*/stack to detect recent setuid/setgid/capset calls
    // For now, this is a best-effort probe based on available /proc data
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            let pid_str = match path.file_name().and_then(|n| n.to_str()) {
                Some(s) if s.chars().all(|c| c.is_ascii_digit()) => s,
                _ => continue,
            };

            let pid: u32 = match pid_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            // Read status file for uid/euid/suid/gid/egid/sgid/capabilities
            let status_path = path.join("status");
            if let Ok(status_content) = std::fs::read_to_string(&status_path) {
                // Parse Uid, Gid, CapEff, CapPrm from /proc/[pid]/status
                let mut uid = None;
                let mut euid = None;
                let mut suid = None;
                let mut gid = None;
                let mut egid = None;
                let mut sgid = None;
                let mut cap_eff = None;
                let mut cap_prm = None;

                for line in status_content.lines() {
                    if let Some(rest) = line.strip_prefix("Uid:") {
                        let parts: Vec<&str> = rest.trim().split_whitespace().collect();
                        if parts.len() >= 4 {
                            uid = parts[0].parse().ok();
                            euid = parts[1].parse().ok();
                            suid = parts[3].parse().ok();
                        }
                    } else if let Some(rest) = line.strip_prefix("Gid:") {
                        let parts: Vec<&str> = rest.trim().split_whitespace().collect();
                        if parts.len() >= 4 {
                            gid = parts[0].parse().ok();
                            egid = parts[1].parse().ok();
                            sgid = parts[3].parse().ok();
                        }
                    } else if let Some(rest) = line.strip_prefix("CapEff:") {
                        cap_eff = Some(rest.trim().to_string());
                    } else if let Some(rest) = line.strip_prefix("CapPrm:") {
                        cap_prm = Some(rest.trim().to_string());
                    }
                }

                // Detect boundary cross: uid != euid (setuid bit set or caps elevated)
                if let (Some(uid_val), Some(euid_val)) = (uid, euid) {
                    if uid_val != euid_val {
                        let exe = read_proc_exe(pid).unwrap_or_else(|| "unknown".to_string());
                        let comm = read_proc_comm(pid).unwrap_or_else(|| "unknown".to_string());

                        let mut fields = BTreeMap::new();
                        fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
                        fields.insert(event_keys::PROC_UID.to_string(), json!(uid_val));
                        fields.insert("euid".to_string(), json!(euid_val));
                        if let Some(suid_val) = suid {
                            fields.insert("suid".to_string(), json!(suid_val));
                        }
                        fields.insert(event_keys::PROC_EXE.to_string(), json!(exe));
                        fields.insert(event_keys::PROC_COMM.to_string(), json!(comm));

                        let mut ev = event_builders::event(
                            host,
                            "attack_surface",
                            "priv_boundary_cross",
                            "high",
                            fields,
                        );
                        ev.tags.extend(vec![
                            "privilege_escalation".to_string(),
                            "boundary_cross".to_string(),
                        ]);
                        events.push(ev);
                    }
                }

                // Detect UID changes (cap_setuid or cap_dac_override implies elevated uid)
                if let (Some(euid_val), Some(uid_val)) = (euid, uid) {
                    if euid_val == 0 && uid_val != 0 {
                        let exe = read_proc_exe(pid).unwrap_or_else(|| "unknown".to_string());
                        let comm = read_proc_comm(pid).unwrap_or_else(|| "unknown".to_string());

                        let mut fields = BTreeMap::new();
                        fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
                        fields.insert(event_keys::PROC_UID.to_string(), json!(uid_val));
                        fields.insert("old_euid".to_string(), json!(uid_val));
                        fields.insert("new_euid".to_string(), json!(0));
                        fields.insert(event_keys::PROC_EXE.to_string(), json!(exe));
                        fields.insert(event_keys::PROC_COMM.to_string(), json!(comm));

                        let mut ev = event_builders::event(
                            host,
                            "attack_surface",
                            "priv_uid_change",
                            "medium",
                            fields,
                        );
                        ev.tags.extend(vec![
                            "privilege_escalation".to_string(),
                            "uid_change".to_string(),
                        ]);
                        events.push(ev);
                    }
                }

                // Detect GID changes
                if let (Some(egid_val), Some(gid_val)) = (egid, gid) {
                    if egid_val == 0 && gid_val != 0 {
                        let exe = read_proc_exe(pid).unwrap_or_else(|| "unknown".to_string());
                        let comm = read_proc_comm(pid).unwrap_or_else(|| "unknown".to_string());

                        let mut fields = BTreeMap::new();
                        fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
                        fields.insert(event_keys::PROC_UID.to_string(), json!(uid.unwrap_or(0)));
                        fields.insert(event_keys::PROC_GID.to_string(), json!(gid_val));
                        fields.insert("old_egid".to_string(), json!(gid_val));
                        fields.insert("new_egid".to_string(), json!(0));
                        fields.insert(event_keys::PROC_EXE.to_string(), json!(exe));
                        fields.insert(event_keys::PROC_COMM.to_string(), json!(comm));

                        let mut ev = event_builders::event(
                            host,
                            "attack_surface",
                            "priv_gid_change",
                            "medium",
                            fields,
                        );
                        ev.tags.extend(vec![
                            "privilege_escalation".to_string(),
                            "gid_change".to_string(),
                        ]);
                        events.push(ev);
                    }
                }

                // Detect capability changes
                if let (Some(cap_eff_val), Some(cap_prm_val)) = (cap_eff, cap_prm) {
                    if cap_eff_val != "0000000000000000" || cap_prm_val != "0000000000000000" {
                        let exe = read_proc_exe(pid).unwrap_or_else(|| "unknown".to_string());
                        let comm = read_proc_comm(pid).unwrap_or_else(|| "unknown".to_string());

                        let mut fields = BTreeMap::new();
                        fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
                        fields.insert(event_keys::PROC_UID.to_string(), json!(uid.unwrap_or(0)));
                        fields.insert(event_keys::PROC_EXE.to_string(), json!(exe));
                        fields.insert(event_keys::PROC_COMM.to_string(), json!(comm));
                        fields.insert("cap_effective".to_string(), json!(cap_eff_val));
                        fields.insert("cap_permitted".to_string(), json!(cap_prm_val));

                        let mut ev = event_builders::event(
                            host,
                            "attack_surface",
                            "priv_cap_change",
                            "high",
                            fields,
                        );
                        ev.tags
                            .extend(vec!["privilege_escalation".to_string(), "caps".to_string()]);
                        events.push(ev);
                    }
                }
            }
        }
    }

    events
}

/// Read exe path from /proc/[pid]/exe
fn read_proc_exe(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{}/exe", pid))
        .ok()
        .and_then(|p| p.to_str().map(|s| s.to_string()))
}

/// Read comm (process name) from /proc/[pid]/comm
fn read_proc_comm(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{}/comm", pid))
        .ok()
        .map(|s| s.trim().to_string())
}

/// Collect network connection events (basic: no state, just per-poll capture)
pub fn collect_net_connect(_host: &HostCtx) -> Vec<Event> {
    // Net connect events will be populated from eBPF tcp_connect events in capture loop
    // This is a placeholder for future procfs-based network monitoring
    Vec::new()
}

/// Collect remote tool execution events (ssh, scp, sftp, rsync, nc, ncat, socat, curl, wget)
pub fn collect_remote_tool_exec(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();
    let remote_tools = [
        "ssh", "scp", "sftp", "rsync", "nc", "ncat", "socat", "curl", "wget",
    ];

    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            let pid_str = match path.file_name().and_then(|n| n.to_str()) {
                Some(s) if s.chars().all(|c| c.is_ascii_digit()) => s,
                _ => continue,
            };

            let pid: u32 = match pid_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            let exe = read_proc_exe(pid).unwrap_or_else(|| String::new());
            let exe_basename = std::path::Path::new(&exe)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");

            // Check if exe basename matches remote tool
            if remote_tools.contains(&exe_basename) {
                let comm = read_proc_comm(pid).unwrap_or_else(|| "unknown".to_string());
                let uid = read_proc_uid(pid).unwrap_or(0);
                let argv = read_proc_cmdline(pid).unwrap_or_default();
                let cwd = read_proc_cwd(pid).unwrap_or_else(|| "unknown".to_string());

                let mut fields = BTreeMap::new();
                fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
                fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
                fields.insert(event_keys::PROC_EXE.to_string(), json!(exe));
                fields.insert(event_keys::PROC_ARGV.to_string(), json!(argv));
                fields.insert(event_keys::PROC_CWD.to_string(), json!(cwd));
                fields.insert(event_keys::PROC_COMM.to_string(), json!(comm));

                let mut ev = event_builders::event(
                    host,
                    "attack_surface",
                    "remote_tool_exec",
                    "medium",
                    fields,
                );
                ev.tags.extend(vec![
                    "lateral_movement".to_string(),
                    "remote_tool".to_string(),
                ]);
                events.push(ev);
            }
        }
    }

    events
}

/// Collect log tampering events (unlink/rename/chmod/chown on log paths)
pub fn collect_log_tamper(host: &HostCtx) -> Vec<Event> {
    // Log tamper detection requires audit/inotify integration
    // This is a placeholder for eBPF-based detection
    // Would monitor file_unlink, file_rename, file_chmod, file_chown syscalls on:
    // /var/log/, /var/tmp/, /tmp/, ~/.bash_history, ~/.zsh_history
    let _log_patterns = [
        "/var/log/",
        "/var/tmp/",
        "/tmp/",
        ".bash_history",
        ".zsh_history",
    ];

    // For now, return empty - this will be populated from eBPF events
    Vec::new()
}

/// Collect audit tampering events (file ops on /etc/audit/, /var/log/audit/, /etc/rsyslog*)
pub fn collect_audit_tamper(host: &HostCtx) -> Vec<Event> {
    // Audit tamper detection requires audit/inotify integration
    let _audit_patterns = ["/etc/audit/", "/var/log/audit/", "/etc/rsyslog"];

    // For now, return empty - this will be populated from eBPF events
    Vec::new()
}

/// Read UID from /proc/[pid]/status
fn read_proc_uid(pid: u32) -> Option<u32> {
    let status_path = format!("/proc/{}/status", pid);
    if let Ok(content) = std::fs::read_to_string(&status_path) {
        for line in content.lines() {
            if let Some(rest) = line.strip_prefix("Uid:") {
                let parts: Vec<&str> = rest.trim().split_whitespace().collect();
                if let Some(uid_str) = parts.first() {
                    if let Ok(uid) = uid_str.parse::<u32>() {
                        return Some(uid);
                    }
                }
                break;
            }
        }
    }
    None
}

/// Read cmdline (argv) from /proc/[pid]/cmdline
fn read_proc_cmdline(pid: u32) -> Option<Vec<String>> {
    let cmdline_path = format!("/proc/{}/cmdline", pid);
    if let Ok(content) = std::fs::read_to_string(&cmdline_path) {
        let argv: Vec<String> = content
            .split('\0')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        if !argv.is_empty() {
            return Some(argv);
        }
    }
    None
}

/// Read cwd (current working directory) from /proc/[pid]/cwd
fn read_proc_cwd(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{}/cwd", pid))
        .ok()
        .and_then(|p| p.to_str().map(|s| s.to_string()))
}
