//! telemetry_fingerprint sensor v2
//! Read-only loader + is_known_good_* helpers; no emit

use crate::core::Event;
use crate::linux::host::HostCtx;
use std::fs;

/// Collect telemetry_fingerprint events - read-only, no events emitted
pub fn collect(_host: &HostCtx) -> Vec<Event> {
    // Load fingerprint data
    let _fingerprints = load_known_good_fingerprints();

    // This sensor is read-only and doesn't emit events
    // It provides is_known_good_* helpers for other sensors
    Vec::new()
}

/// Known-good fingerprints data structure
#[derive(Clone, Debug)]
pub struct FingerprintDatabase {
    pub known_good_binaries: Vec<String>,
    pub known_good_hashes: Vec<String>,
    pub known_good_signatures: Vec<String>,
}

/// Load known-good fingerprints from bundled data
fn load_known_good_fingerprints() -> FingerprintDatabase {
    // Try to load from /etc or bundled location
    let db = FingerprintDatabase {
        known_good_binaries: vec![
            "/bin/bash".to_string(),
            "/bin/sh".to_string(),
            "/bin/ls".to_string(),
            "/bin/cat".to_string(),
            "/usr/bin/sudo".to_string(),
        ],
        known_good_hashes: vec![
            // SHA256 hashes of known-good binaries
            // (would load from actual database in production)
        ],
        known_good_signatures: vec![],
    };

    // Try to load from bundled JSON file if it exists
    if let Ok(content) = fs::read_to_string("/etc/edr/fingerprints.json") {
        // Simple parsing without serde for now
        if content.contains("known_good_binaries") {
            // In production, would use proper JSON parsing
            // For now, just indicate successful load
            let _ = content;
        }
    }

    db
}

/// Check if a binary path is known-good
pub fn is_known_good_binary(path: &str) -> bool {
    let db = load_known_good_fingerprints();
    db.known_good_binaries.iter().any(|b| b == path)
}

/// Check if a hash is known-good
pub fn is_known_good_hash(hash: &str) -> bool {
    let db = load_known_good_fingerprints();
    db.known_good_hashes.iter().any(|h| h == hash)
}

/// Check if a signature is known-good
pub fn is_known_good_signature(sig: &str) -> bool {
    let db = load_known_good_fingerprints();
    db.known_good_signatures.iter().any(|s| s == sig)
}
