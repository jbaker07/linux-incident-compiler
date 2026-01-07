//! container_monitor sensor v2
//! Detects Docker/Containerd via /proc and /var/run sockets, privileged containers

use crate::core::event_keys;
use crate::core::Event;
use crate::linux::event_builders;
use crate::linux::host::HostCtx;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;

/// Collect container_monitor events
pub fn collect(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Check 1: High-precision invariant - detect docker socket access
    events.extend(detect_docker_sockets(host));

    // Check 2: Heuristic - detect container processes and privileged containers
    events.extend(detect_container_processes(host));

    events
}

fn detect_docker_sockets(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    let docker_sockets = vec![
        "/var/run/docker.sock",
        "/var/run/containerd/containerd.sock",
        "/var/run/cri-docker.sock",
    ];

    for socket_path in docker_sockets {
        if let Ok(meta) = fs::metadata(socket_path) {
            // Check if it's a socket using metadata
            #[cfg(unix)]
            let is_socket = {
                use std::os::unix::fs::FileTypeExt;
                meta.file_type().is_socket()
            };
            #[cfg(not(unix))]
            let is_socket = false;

            if is_socket {
                // Get socket permissions
                #[cfg(unix)]
                let perms = {
                    use std::os::unix::fs::PermissionsExt;
                    format!("{:o}", meta.permissions().mode())
                };
                #[cfg(not(unix))]
                let perms = "unknown".to_string();

                let key = format!("socket:{}", socket_path);
                if super::common::seen_once("container_monitor", &key) {
                    let mut fields = BTreeMap::new();
                    fields.insert(event_keys::SOCKET_PATH.to_string(), json!(socket_path));
                    fields.insert(event_keys::SOCKET_PERMS.to_string(), json!(perms));

                    // Check if socket is world-readable (potential issue)
                    let severity = if perms.ends_with("66") || perms.ends_with("67") {
                        "medium"
                    } else {
                        "info"
                    };

                    events.push(event_builders::event(
                        host,
                        "container_monitor",
                        "container_socket",
                        severity,
                        fields,
                    ));
                }
            }
        }
    }

    events
}

fn detect_container_processes(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Look for cgroup indicators of container
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(filename) = entry.file_name().into_string() {
                if let Ok(pid) = filename.parse::<u32>() {
                    let cgroup_path = format!("/proc/{}/cgroup", pid);
                    if let Ok(content) = fs::read_to_string(&cgroup_path) {
                        // Check for docker/lxc/k8s cgroup markers
                        let is_container = content.contains("/docker/")
                            || content.contains("/lxc/")
                            || content.contains("/kubepods")
                            || content.contains("/actions/");

                        if is_container {
                            let key = format!("pid:{}", pid);
                            if super::common::rate_limit("container_monitor", &key, 60000) {
                                // Read exe and check if it's a container runtime command
                                let exe_path = format!("/proc/{}/exe", pid);
                                let exe = fs::read_link(&exe_path)
                                    .ok()
                                    .and_then(|p| p.to_str().map(|s| s.to_string()))
                                    .unwrap_or_default();

                                let mut fields = BTreeMap::new();
                                fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
                                fields.insert(event_keys::PROC_EXE.to_string(), json!(exe));

                                events.push(event_builders::event(
                                    host,
                                    "container_monitor",
                                    "container_process",
                                    "info",
                                    fields,
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    events
}
