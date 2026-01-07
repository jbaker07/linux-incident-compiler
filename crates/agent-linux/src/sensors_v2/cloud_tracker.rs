//! cloud_tracker sensor v2
//! Detects AWS/Azure/GCP execution via /proc snapshots and config dir changes

use crate::core::Event;
use crate::linux::event_builders;
use crate::linux::host::HostCtx;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// Collect cloud_tracker events - detect cloud platform tools and config changes
pub fn collect(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Check 1: High-precision invariant - detect cloud CLI execution from /proc
    events.extend(detect_cloud_cli_execution(host));

    // Check 2: Heuristic - detect config directory changes
    events.extend(detect_config_changes(host));

    events
}

fn detect_cloud_cli_execution(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Cloud CLI executables to look for
    let cloud_exes = vec![
        ("aws", "AWS CLI"),
        ("az", "Azure CLI"),
        ("gcloud", "Google Cloud SDK"),
        ("kubectl", "Kubernetes"),
        ("terraform", "Terraform"),
    ];

    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(filename) = entry.file_name().into_string() {
                if let Ok(pid) = filename.parse::<u32>() {
                    let cmdline_path = format!("/proc/{}/cmdline", pid);
                    if let Ok(bytes) = fs::read(&cmdline_path) {
                        let cmdline = String::from_utf8_lossy(&bytes);

                        for (exe_name, cloud_name) in &cloud_exes {
                            if cmdline.contains(exe_name) {
                                let key = format!("cloud_cli:{}", exe_name);
                                if super::common::seen_once("cloud_tracker", &key) {
                                    let mut fields = BTreeMap::new();
                                    fields.insert("pid".to_string(), json!(pid));
                                    fields.insert("exe".to_string(), json!(exe_name.to_string()));
                                    fields.insert(
                                        "platform".to_string(),
                                        json!(cloud_name.to_string()),
                                    );
                                    fields
                                        .insert("cmdline".to_string(), json!(cmdline.to_string()));

                                    events.push(event_builders::event(
                                        host,
                                        "cloud_tracker",
                                        "cloud_execution",
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
    }

    events
}

fn detect_config_changes(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    let config_dirs = vec![
        (".aws", "AWS"),
        (".config/gcloud", "Google Cloud"),
        (".azure", "Azure"),
    ];

    if let Ok(home) = std::env::var("HOME") {
        for (dir_name, platform) in config_dirs {
            let config_path = format!("{}/{}", home, dir_name);
            let path = Path::new(&config_path);

            if path.exists() && path.is_dir() {
                // Check for credentials or config files
                if let Ok(entries) = fs::read_dir(&config_path) {
                    for entry in entries.flatten() {
                        if let Ok(name) = entry.file_name().into_string() {
                            if name.contains("credentials") || name.contains("config") {
                                let key = format!("config:{}:{}", platform, name);
                                if super::common::rate_limit("cloud_tracker", &key, 3600000) {
                                    let mut fields = BTreeMap::new();
                                    fields.insert("platform".to_string(), json!(platform));
                                    fields.insert("config_dir".to_string(), json!(dir_name));
                                    fields.insert("file".to_string(), json!(name));

                                    events.push(event_builders::event(
                                        host,
                                        "cloud_tracker",
                                        "cloud_config",
                                        "info",
                                        fields,
                                    ));
                                }
                                break; // One event per directory
                            }
                        }
                    }
                }
            }
        }
    }

    events
}
