//! suspicious_ipc sensor v2
//! /proc/net/unix + /dev/shm anomalies; unknown sockets, weird perms/owners

use crate::core::Event;
use crate::linux::event_builders;
use crate::linux::host::HostCtx;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;

/// Collect suspicious_ipc events
pub fn collect(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Check 1: High-precision invariant - unknown/suspicious Unix sockets
    events.extend(detect_suspicious_sockets(host));

    // Check 2: Heuristic - /dev/shm anomalies
    events.extend(detect_devshm_anomalies(host));

    events
}

fn detect_suspicious_sockets(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Read /proc/net/unix for socket list
    if let Ok(content) = fs::read_to_string("/proc/net/unix") {
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 8 {
                continue;
            }

            let socket_path = if let Some(path) = parts.last() {
                *path
            } else {
                continue;
            };

            // Skip well-known system sockets
            if is_well_known_socket(socket_path) {
                continue;
            }

            // Check for suspicious socket patterns
            if is_suspicious_socket_name(socket_path) {
                let key = format!("socket:{}", socket_path);
                if super::common::seen_once("suspicious_ipc", &key) {
                    let mut fields = BTreeMap::new();
                    fields.insert("socket_path".to_string(), json!(socket_path));
                    fields.insert("ref_count".to_string(), json!(parts.get(3).unwrap_or(&"0")));

                    events.push(event_builders::event(
                        host,
                        "suspicious_ipc",
                        "suspicious_socket",
                        "medium",
                        fields,
                    ));
                }
            }

            // Check if socket exists and has unusual permissions
            if let Ok(meta) = fs::metadata(socket_path) {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = meta.permissions().mode();
                    let perms = format!("{:o}", mode);

                    // World-writable socket is suspicious
                    if mode & 0o002 != 0 {
                        let key = format!("world_writable:{}", socket_path);
                        if super::common::rate_limit("suspicious_ipc", &key, 3600000) {
                            let mut fields = BTreeMap::new();
                            fields.insert("socket_path".to_string(), json!(socket_path));
                            fields.insert("perms".to_string(), json!(perms));
                            fields.insert("world_writable".to_string(), json!(true));

                            events.push(event_builders::event(
                                host,
                                "suspicious_ipc",
                                "world_writable_socket",
                                "high",
                                fields,
                            ));
                        }
                    }
                }
            }
        }
    }

    events
}

fn detect_devshm_anomalies(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Monitor /dev/shm for suspicious shared memory segments
    if let Ok(entries) = fs::read_dir("/dev/shm") {
        for entry in entries.flatten() {
            if let Ok(path) = entry.path().into_os_string().into_string() {
                if let Ok(meta) = fs::metadata(&path) {
                    let filename = entry.file_name();
                    let name = filename.to_string_lossy();

                    // Check for suspicious names (contain hidden markers, etc)
                    if is_suspicious_shm_name(&name) {
                        let key = format!("shm:{}", name);
                        if super::common::seen_once("suspicious_ipc", &key) {
                            let mut fields = BTreeMap::new();
                            fields.insert("shm_name".to_string(), json!(name.to_string()));
                            fields.insert("path".to_string(), json!(path));
                            fields.insert("size_bytes".to_string(), json!(meta.len()));

                            events.push(event_builders::event(
                                host,
                                "suspicious_ipc",
                                "suspicious_shm",
                                "medium",
                                fields,
                            ));
                        }
                    }

                    // Check for large shared memory segments
                    if meta.len() > 100_000_000 {
                        // > 100MB
                        let key = format!("large_shm:{}", name);
                        if super::common::rate_limit("suspicious_ipc", &key, 3600000) {
                            let mut fields = BTreeMap::new();
                            fields.insert("shm_name".to_string(), json!(name.to_string()));
                            fields.insert(
                                "size_mb".to_string(),
                                json!(meta.len() as f64 / 1_000_000.0),
                            );

                            events.push(event_builders::event(
                                host,
                                "suspicious_ipc",
                                "large_shm",
                                "info",
                                fields,
                            ));
                        }
                    }
                }
            }
        }
    }

    events
}

/// Check if socket path is a well-known system socket
fn is_well_known_socket(path: &str) -> bool {
    let well_known = vec![
        "systemd",
        "dbus",
        "udev",
        "pulseaudio",
        "run/acpid.socket",
        "docker.sock",
        "rpc_pipefs",
        ".X11-unix",
        "snapd",
    ];

    well_known.iter().any(|wk| path.contains(wk))
}

/// Check if socket name looks suspicious
fn is_suspicious_socket_name(name: &str) -> bool {
    let suspicious_patterns = vec![
        "hidden", "secret", "stealth", "backdoor", "exploit", "rootkit", "\x00", // null bytes
        "..\\", // path traversal
    ];

    suspicious_patterns
        .iter()
        .any(|pattern| name.contains(pattern))
}

/// Check if shared memory name looks suspicious
fn is_suspicious_shm_name(name: &str) -> bool {
    // Hidden files in /dev/shm
    if name.starts_with('.') && name.len() > 1 && name.chars().skip(1).all(|c| c.is_numeric()) {
        return true;
    }

    let suspicious = vec!["hidden", "payload", "backdoor", "exploit", "xor"];

    suspicious.iter().any(|s| name.to_lowercase().contains(s))
}
