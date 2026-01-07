//! lkm_monitor sensor v2
//! /proc/modules + /sys/module deltas; emit on new module; basic tamper heuristics

use crate::core::Event;
use crate::linux::event_builders;
use crate::linux::host::HostCtx;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;

/// Collect lkm_monitor events - kernel module monitoring
pub fn collect(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Check 1: High-precision invariant - new kernel modules loaded
    events.extend(detect_new_modules(host));

    // Check 2: Heuristic - suspicious module characteristics
    events.extend(detect_suspicious_modules(host));

    events
}

fn detect_new_modules(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Read /proc/modules
    if let Ok(content) = fs::read_to_string("/proc/modules") {
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            let module_name = parts[0];
            let module_size = parts.get(1).unwrap_or(&"0");
            let use_count = parts.get(2).unwrap_or(&"0");

            // Track new modules
            if super::common::seen_once("lkm_monitor", module_name) {
                let mut fields = BTreeMap::new();
                fields.insert("module_name".to_string(), json!(module_name));
                fields.insert("size".to_string(), json!(module_size.to_string()));
                fields.insert("use_count".to_string(), json!(use_count.to_string()));

                // Check if module looks suspicious (unusual name pattern)
                let is_suspicious = is_suspicious_module_name(module_name);

                events.push(event_builders::event(
                    host,
                    "lkm_monitor",
                    "kernel_module_loaded",
                    if is_suspicious { "high" } else { "info" },
                    fields,
                ));
            }
        }
    }

    events
}

fn detect_suspicious_modules(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Check /sys/module for tamper indicators
    if let Ok(entries) = fs::read_dir("/sys/module") {
        for entry in entries.flatten() {
            if let Ok(path) = entry.path().into_os_string().into_string() {
                // Extract module name from path
                let module_name = path.split('/').last().unwrap_or("unknown");

                // Check for license tamper (modules without proper license are suspicious)
                let license_path = format!("{}/license", path);
                let has_license = fs::read_to_string(&license_path).is_ok();

                // Check for signature verification
                let signature_path = format!("{}/signature", path);
                let has_signature = fs::read_to_string(&signature_path).is_ok();

                if !has_license {
                    let key = format!("no_license:{}", module_name);
                    if super::common::rate_limit("lkm_monitor", &key, 3600000) {
                        let mut fields = BTreeMap::new();
                        fields.insert("module_name".to_string(), json!(module_name));
                        fields.insert("has_license".to_string(), json!(false));
                        fields.insert("has_signature".to_string(), json!(has_signature));

                        events.push(event_builders::event(
                            host,
                            "lkm_monitor",
                            "module_tamper",
                            "medium",
                            fields,
                        ));
                    }
                }
            }
        }
    }

    events
}

/// Check if module name looks suspicious
fn is_suspicious_module_name(name: &str) -> bool {
    let suspicious_patterns = vec![
        "rootkit", "backdoor", "exploit", "malware", "xor", "hide", "hook", "shadow", "ghost",
        "stealth", "virus", "worm",
    ];

    suspicious_patterns
        .iter()
        .any(|pattern| name.to_lowercase().contains(pattern))
}
