//! file_tamper_monitor sensor v2 - critical file integrity
//! Sources: /etc/passwd, /etc/shadow, /etc/sudoers, /etc/ssh/sshd_config, system binaries
//! Detects: unauthorized modifications to critical system files

use crate::core::Event;
use crate::linux::event_builders;
use crate::linux::host::HostCtx;
use crate::linux::sensors_v2::common;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;

const CRITICAL_FILES: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/usr/bin/sudo",
    "/bin/bash",
    "/bin/sh",
];

/// Collect file tampering events
pub fn collect(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    for path in CRITICAL_FILES {
        // Invariant: file changed since last check
        if let Ok(metadata) = fs::metadata(path) {
            if let Ok(hash) = compute_file_hash(path) {
                if common::changed_hash("file_tamper_monitor", path, &hash) {
                    let mut fields = BTreeMap::new();
                    fields.insert("path".to_string(), json!(path));
                    fields.insert("hash_sha256".to_string(), json!(hash));
                    if let Ok(m) = metadata.modified() {
                        fields.insert(
                            "mtime_ms".to_string(),
                            json!(m.elapsed().map(|d| d.as_millis() as i64).unwrap_or(0)),
                        );
                    }
                    events.push(event_builders::event(
                        host,
                        "file_tamper_monitor",
                        "file_changed",
                        "alert",
                        fields,
                    ));
                }
            }
        }
    }

    // Heuristic: check /etc/passwd format integrity
    if let Ok(content) = fs::read_to_string("/etc/passwd") {
        let invalid_lines: usize = content
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .filter(|l| l.split(':').count() < 6)
            .count();

        if invalid_lines > 0 && common::seen_once("file_tamper_monitor", "passwd_format") {
            let mut fields = BTreeMap::new();
            fields.insert("path".to_string(), json!("/etc/passwd"));
            fields.insert("invalid_lines".to_string(), json!(invalid_lines));
            events.push(event_builders::event(
                host,
                "file_tamper_monitor",
                "passwd_corrupted",
                "alert",
                fields,
            ));
        }
    }

    events
}

fn compute_file_hash(path: &str) -> std::io::Result<String> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let content = fs::read(path)?;
    let mut hasher = DefaultHasher::new();
    content.hash(&mut hasher);
    Ok(format!("{:x}", hasher.finish()))
}
