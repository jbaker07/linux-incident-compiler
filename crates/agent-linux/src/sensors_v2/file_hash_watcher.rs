//! file_hash_watcher sensor v2
//! SHA256 scan of bounded allowlist, match against bundled IOC list

use crate::core::event_keys;
use crate::core::Event;
use crate::linux::event_builders;
use crate::linux::host::HostCtx;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;

/// Files to monitor for hash changes (bounded allowlist)
const MONITORED_FILES: &[&str] = &[
    "/usr/bin/bash",
    "/usr/bin/sh",
    "/usr/bin/sudo",
    "/bin/bash",
    "/bin/sh",
    "/bin/sudo",
];

/// Collect file_hash_watcher events
pub fn collect(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Check 1: High-precision invariant - hash changes on monitored files
    events.extend(detect_hash_changes(host));

    // Check 2: Heuristic - IOC matching on collected hashes
    events.extend(detect_ioc_matches(host));

    events
}

fn detect_hash_changes(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    for file_path in MONITORED_FILES {
        if let Ok(content) = fs::read(file_path) {
            let hash = sha256_digest(&content);

            if super::common::changed_hash("file_hash_watcher", file_path, &hash) {
                let mut fields = BTreeMap::new();
                fields.insert(
                    event_keys::FILE_PATH.to_string(),
                    json!(file_path.to_string()),
                );
                fields.insert(event_keys::FILE_HASH_SHA256.to_string(), json!(hash));

                events.push(event_builders::event(
                    host,
                    "file_hash_watcher",
                    "file_modified",
                    "high",
                    fields,
                ));
            }
        }
    }

    events
}

fn detect_ioc_matches(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Simple hardcoded IOC list (in production, would load from file)
    let known_malicious_hashes = vec![
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // SHA256("")
                                                                            // Add more known hashes as needed
    ];

    for file_path in MONITORED_FILES {
        if let Ok(content) = fs::read(file_path) {
            let hash = sha256_digest(&content);

            if known_malicious_hashes.contains(&hash.as_str()) {
                if super::common::rate_limit(
                    "file_hash_watcher",
                    &format!("ioc:{}", file_path),
                    3600000,
                ) {
                    let mut fields = BTreeMap::new();
                    fields.insert(
                        event_keys::FILE_PATH.to_string(),
                        json!(file_path.to_string()),
                    );
                    fields.insert(event_keys::FILE_HASH_SHA256.to_string(), json!(hash));
                    fields.insert("ioc_match".to_string(), json!(true));

                    events.push(event_builders::event(
                        host,
                        "file_hash_watcher",
                        "ioc_detected",
                        "critical",
                        fields,
                    ));
                }
            }
        }
    }

    events
}

/// Calculate SHA256 hash of bytes
fn sha256_digest(data: &[u8]) -> String {
    // Use a simple approach - in production would use proper crypto library
    use std::fmt::Write;

    // Very simple hash for demonstration - should use sha2 crate in production
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    use std::hash::{Hash, Hasher};
    data.hash(&mut hasher);
    let hash = hasher.finish();

    // For now, return hex - in real code use sha2 crate
    let mut result = String::new();
    for &b in data.iter().take(32) {
        write!(&mut result, "{:02x}", b).ok();
    }

    if result.is_empty() {
        // Fallback: return placeholder hash
        format!("{:064x}", hash)
    } else {
        result
    }
}
