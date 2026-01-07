//! Procfs process sensor - lists processes from /proc
//! Pure event emitter, no side effects

use crate::core::event_keys;
use crate::core::Event;
use crate::linux::event_builders;
use crate::linux::host::HostCtx;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;

/// Collect process events from /proc filesystem
pub fn collect(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(filename) = entry.file_name().into_string() {
                if let Ok(pid) = filename.parse::<u32>() {
                    if let Ok(event) = read_process_event(host, pid) {
                        events.push(event);
                    }
                }
            }
        }
    }

    events
}

/// Read a single process from /proc/{pid}
fn read_process_event(host: &HostCtx, pid: u32) -> std::io::Result<Event> {
    let procfs_path = format!("/proc/{}", pid);

    // Read basic process info
    let stat_path = format!("{}/stat", procfs_path);
    let stat = fs::read_to_string(&stat_path)?;
    let parts: Vec<&str> = stat.split_whitespace().collect();

    if parts.len() < 4 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid stat format",
        ));
    }

    let ppid = parts[3].parse::<u32>().unwrap_or(0);
    let state = parts[2].chars().next().unwrap_or('?');

    // Read uid/gid from status
    let status_path = format!("{}/status", procfs_path);
    let status = fs::read_to_string(&status_path)?;
    let mut uid = 0u32;
    let mut gid = 0u32;

    for line in status.lines() {
        if line.starts_with("Uid:") {
            if let Some(first) = line.split_whitespace().nth(1) {
                uid = first.parse().unwrap_or(0);
            }
        }
        if line.starts_with("Gid:") {
            if let Some(first) = line.split_whitespace().nth(1) {
                gid = first.parse().unwrap_or(0);
            }
        }
    }

    // Read command line
    let cmdline_path = format!("{}/cmdline", procfs_path);
    let cmdline_bytes = fs::read(&cmdline_path).unwrap_or_default();
    let args: Vec<String> = cmdline_bytes
        .split(|&b| b == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).to_string())
        .collect();

    let exe = args.first().cloned().unwrap_or_default();

    // Build Event
    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_PPID.to_string(), json!(ppid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_GID.to_string(), json!(gid));
    fields.insert(event_keys::PROC_STATE.to_string(), json!(state.to_string()));
    fields.insert(event_keys::PROC_EXE.to_string(), json!(exe));
    fields.insert(event_keys::PROC_ARGV.to_string(), json!(args));

    Ok(event_builders::process_event(
        host,
        "procfs_process",
        pid,
        ppid,
        &exe,
        fields,
    ))
}
