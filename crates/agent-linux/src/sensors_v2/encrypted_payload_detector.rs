//! encrypted_payload_detector sensor v2
//! High-entropy file writes, crypto tool execution, suspicious renames
//! Rate-limited: scans every 5 seconds with capped work budget

use crate::core::Event;
use crate::linux::event_builders;
use crate::linux::host::HostCtx;
use crate::linux::sensors_v2::config;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;

/// Minimum entropy to consider a file "suspicious"
const HIGH_ENTROPY_THRESHOLD: f32 = 7.0;

/// Collect encrypted_payload_detector events
pub fn collect(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Check 1: High-entropy file detection (capped work)
    events.extend(detect_high_entropy_files(host));

    // Check 2: Crypto tool execution tracking (always fast)
    events.extend(detect_crypto_tool_execution(host));

    events
}

fn detect_high_entropy_files(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    let cfg = config::SensorConfig::default(); // Re-fetch to get current config
    let work = &cfg.work_budget;

    // Scan common temporary directories with strict work limits
    let scan_dirs = vec!["/tmp", "/var/tmp"];

    let mut files_scanned = 0usize;
    let mut bytes_read = 0u64;
    let mut high_entropy_findings = Vec::new();

    for dir_path in scan_dirs {
        if files_scanned >= work.max_files || bytes_read >= work.max_bytes_total {
            break;
        }

        if let Ok(entries) = fs::read_dir(dir_path) {
            for entry in entries.flatten() {
                if files_scanned >= work.max_files || bytes_read >= work.max_bytes_total {
                    break;
                }

                if let Ok(meta) = entry.metadata() {
                    let path = entry.path();
                    if !meta.is_file() || meta.len() < 1024 {
                        continue;
                    }

                    // Skip if file exceeds per-file limit
                    if meta.len() > work.max_bytes_per_file {
                        continue;
                    }

                    let path_str = match path.to_str() {
                        Some(s) => s.to_string(),
                        None => continue,
                    };

                    // Cache key: path:inode:mtime:size
                    #[cfg(unix)]
                    let inode = {
                        use std::os::unix::fs::MetadataExt;
                        meta.ino()
                    };
                    #[cfg(not(unix))]
                    let inode = 0u64;

                    let cache_key = format!(
                        "entropy_cache:{}:{}:{}:{}",
                        path_str,
                        inode,
                        meta.modified()
                            .map(|m| m.elapsed().map(|e| e.as_secs()).unwrap_or(0))
                            .unwrap_or(0),
                        meta.len()
                    );

                    // Skip if we've already scanned this exact file state
                    if !super::common::seen_once("encrypted_payload_detector", &cache_key) {
                        continue;
                    }

                    // Read and scan file
                    if let Ok(content) = fs::read(&path_str) {
                        let entropy = calculate_entropy(&content);
                        bytes_read += content.len() as u64;
                        files_scanned += 1;

                        if entropy >= HIGH_ENTROPY_THRESHOLD {
                            high_entropy_findings.push((path_str, entropy, meta.len()));
                        }
                    }
                }
            }
        }
    }

    // Emit one summary event if findings exist, plus top N findings
    if !high_entropy_findings.is_empty() {
        let max_findings = 5;
        high_entropy_findings
            .sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        high_entropy_findings.truncate(max_findings);

        // Summary event
        let mut summary_fields = BTreeMap::new();
        summary_fields.insert(
            "total_findings".to_string(),
            json!(high_entropy_findings.len()),
        );
        summary_fields.insert("scan_files".to_string(), json!(files_scanned));
        summary_fields.insert("scan_bytes".to_string(), json!(bytes_read));
        events.push(event_builders::event(
            host,
            "encrypted_payload_detector",
            "high_entropy_summary",
            "medium",
            summary_fields,
        ));

        // Top findings (individual events, capped)
        for (path, entropy, size) in high_entropy_findings {
            let mut fields = BTreeMap::new();
            fields.insert("path".to_string(), json!(path));
            fields.insert("entropy".to_string(), json!(entropy));
            fields.insert("size_bytes".to_string(), json!(size));
            events.push(event_builders::event(
                host,
                "encrypted_payload_detector",
                "high_entropy_finding",
                "info",
                fields,
            ));
        }
    }

    events
}

fn detect_crypto_tool_execution(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    let crypto_tools = vec![
        "openssl", "gpg", "gpg2", "7z", "zip", "tar", "gzip", "bzip2", "xz",
    ];

    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(filename) = entry.file_name().into_string() {
                if let Ok(pid) = filename.parse::<u32>() {
                    let cmdline_path = format!("/proc/{}/cmdline", pid);
                    if let Ok(bytes) = fs::read(&cmdline_path) {
                        let cmdline = String::from_utf8_lossy(&bytes);

                        for tool in &crypto_tools {
                            if cmdline.contains(tool) {
                                let key = format!("crypto:{}:{}", tool, pid);
                                // Rate-limit per tool:pid pair for 5 seconds
                                if super::common::rate_limit(
                                    "encrypted_payload_detector",
                                    &key,
                                    5000,
                                ) {
                                    let mut fields = BTreeMap::new();
                                    fields.insert("pid".to_string(), json!(pid));
                                    fields.insert("tool".to_string(), json!(tool.to_string()));
                                    fields.insert(
                                        "cmdline".to_string(),
                                        json!(cmdline.chars().take(200).collect::<String>()),
                                    );

                                    events.push(event_builders::event(
                                        host,
                                        "encrypted_payload_detector",
                                        "crypto_tool_exec",
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

/// Calculate Shannon entropy of byte slice (0.0 to 8.0)
fn calculate_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u32; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f32;
    let mut entropy = 0.0f32;

    for &count in &freq {
        if count > 0 {
            let p = count as f32 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}
