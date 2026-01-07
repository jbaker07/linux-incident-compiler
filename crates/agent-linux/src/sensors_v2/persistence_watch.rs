//! persistence_watch sensor v2 - persistence mechanism detection
//! Sources: ~/.bashrc, ~/.profile, /etc/profile.d/, /etc/init.d/, cron files
//! Detects: new persistence hooks, script drops, cron modifications, shell startup changes

use crate::core::Event;
use crate::linux::event_builders;
use crate::linux::host::HostCtx;
use crate::linux::sensors_v2::common;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;

/// Persistence paths to monitor
/// Reserved for file-based persistence monitoring; not yet enabled.
const PERSISTENCE_PATHS: &[&str] = &[
    "~/.bashrc",
    "~/.bash_profile",
    "~/.zshrc",
    "/etc/profile.d/",
    "/etc/cron.d/",
    "/var/spool/cron/",
    "/etc/rc.local",
    "/etc/init.d/",
];

/// Collect persistence mechanism events
pub fn collect(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Check shell startup files
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    for fname in &["/.bashrc", "/.bash_profile", "/.zshrc"] {
        let path = format!("{}{}", home, fname);
        if let Ok(content) = fs::read_to_string(&path) {
            // Invariant: suspicious content in shell startup
            if content.contains("export") && content.contains("LD_PRELOAD") {
                if common::seen_once("persistence_watch", &path) {
                    let mut fields = BTreeMap::new();
                    fields.insert("path".to_string(), json!(path));
                    fields.insert("detection".to_string(), json!("ld_preload_startup"));
                    events.push(event_builders::event(
                        host,
                        "persistence_watch",
                        "persistence_hook",
                        "warn",
                        fields,
                    ));
                }
            }
        }
    }

    // Check /etc/profile.d/
    if let Ok(dir) = fs::read_dir("/etc/profile.d") {
        for entry in dir.flatten() {
            if let Ok(content) = fs::read_to_string(entry.path()) {
                if content.contains("nc ")
                    || content.contains("bash -i")
                    || content.contains("/dev/tcp")
                {
                    let path_str = entry.path().to_string_lossy().to_string();
                    if common::rate_limit("persistence_watch", &path_str, 86400_000) {
                        let mut fields = BTreeMap::new();
                        fields.insert("path".to_string(), json!(path_str.clone()));
                        fields.insert("detection".to_string(), json!("suspicious_profile"));
                        events.push(event_builders::event(
                            host,
                            "persistence_watch",
                            "profile_injection",
                            "alert",
                            fields,
                        ));
                    }
                }
            }
        }
    }

    // Check cron modifications
    if let Ok(cron_dir) = fs::read_dir("/etc/cron.d") {
        for entry in cron_dir.flatten() {
            if let Ok(content) = fs::read_to_string(entry.path()) {
                for line in content.lines() {
                    if !line.starts_with('#')
                        && line.contains(';')
                        && (line.contains("curl") || line.contains("wget"))
                    {
                        let path_str = entry.path().to_string_lossy().to_string();
                        if common::seen_once("persistence_watch", &path_str) {
                            let mut fields = BTreeMap::new();
                            fields.insert("path".to_string(), json!(path_str));
                            events.push(event_builders::event(
                                host,
                                "persistence_watch",
                                "cron_suspicious",
                                "warn",
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
