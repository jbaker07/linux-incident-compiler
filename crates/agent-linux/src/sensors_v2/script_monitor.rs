//! script_monitor sensor v2
//! Detect new scripts in /tmp, /var/tmp, home; interpreter-from-writable

use crate::core::Event;
use crate::linux::event_builders;
use crate::linux::host::HostCtx;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;

/// Common script interpreters
const SCRIPT_INTERPRETERS: &[&str] = &[
    "#!/bin/bash",
    "#!/bin/sh",
    "#!/usr/bin/python",
    "#!/usr/bin/perl",
    "#!/usr/bin/ruby",
];
const WRITABLE_DIRS: &[&str] = &["/tmp", "/var/tmp", "/dev/shm"];

/// Collect script_monitor events
pub fn collect(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Check 1: High-precision invariant - detect new scripts in writable dirs
    events.extend(detect_new_scripts(host));

    // Check 2: Heuristic - interpreter execution from writable paths
    events.extend(detect_interpreter_execution(host));

    events
}

fn detect_new_scripts(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    for dir in WRITABLE_DIRS {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                if let Ok(path) = entry.path().into_os_string().into_string() {
                    if let Ok(meta) = fs::metadata(&path) {
                        if meta.is_file() {
                            // Try to detect if it's a script
                            if let Ok(content) = fs::read(&path) {
                                if content.len() < 100_000 {
                                    let header = String::from_utf8_lossy(
                                        &content[..std::cmp::min(20, content.len())],
                                    );

                                    // Check for shebang
                                    for interp in SCRIPT_INTERPRETERS {
                                        if header.contains(interp) {
                                            let key = format!("script:{}", path);
                                            if super::common::seen_once("script_monitor", &key) {
                                                let mut fields = BTreeMap::new();
                                                fields.insert(
                                                    "path".to_string(),
                                                    json!(path.clone()),
                                                );
                                                fields.insert(
                                                    "directory".to_string(),
                                                    json!(dir.to_string()),
                                                );
                                                fields.insert(
                                                    "interpreter".to_string(),
                                                    json!(interp.to_string()),
                                                );
                                                fields.insert(
                                                    "size_bytes".to_string(),
                                                    json!(meta.len()),
                                                );

                                                events.push(event_builders::event(
                                                    host,
                                                    "script_monitor",
                                                    "script_created",
                                                    "medium",
                                                    fields,
                                                ));
                                            }
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Check home directory
    if let Ok(home) = std::env::var("HOME") {
        for subdir in &[".", ".local", ".config", ".cache"] {
            let check_dir = format!("{}/{}", home, subdir);
            if let Ok(entries) = fs::read_dir(&check_dir) {
                for entry in entries.flatten() {
                    if let Ok(path) = entry.path().into_os_string().into_string() {
                        if let Ok(meta) = fs::metadata(&path) {
                            if meta.is_file() && (path.ends_with(".sh") || path.ends_with(".py")) {
                                let key = format!("home_script:{}", path);
                                if super::common::rate_limit("script_monitor", &key, 3600000) {
                                    let mut fields = BTreeMap::new();
                                    fields.insert("path".to_string(), json!(path));
                                    fields.insert("size_bytes".to_string(), json!(meta.len()));

                                    events.push(event_builders::event(
                                        host,
                                        "script_monitor",
                                        "home_script",
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

fn detect_interpreter_execution(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    let interpreters = vec![
        ("bash", "/bin/bash"),
        ("sh", "/bin/sh"),
        ("python", "/usr/bin/python"),
        ("python3", "/usr/bin/python3"),
        ("perl", "/usr/bin/perl"),
        ("ruby", "/usr/bin/ruby"),
    ];

    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(filename) = entry.file_name().into_string() {
                if let Ok(pid) = filename.parse::<u32>() {
                    let cmdline_path = format!("/proc/{}/cmdline", pid);
                    if let Ok(bytes) = fs::read(&cmdline_path) {
                        let cmdline = String::from_utf8_lossy(&bytes);

                        for (interp_name, _interp_path) in &interpreters {
                            if cmdline.contains(interp_name) {
                                // Check if executing script from writable dir
                                let args: Vec<&str> = cmdline.split('\0').collect();
                                if let Some(script_arg) = args.get(1) {
                                    for writable_dir in WRITABLE_DIRS {
                                        if script_arg.starts_with(writable_dir) {
                                            let key = format!("interp_exec:{}:{}", pid, script_arg);
                                            if super::common::rate_limit(
                                                "script_monitor",
                                                &key,
                                                5000,
                                            ) {
                                                let mut fields = BTreeMap::new();
                                                fields.insert("pid".to_string(), json!(pid));
                                                fields.insert(
                                                    "interpreter".to_string(),
                                                    json!(interp_name.to_string()),
                                                );
                                                fields.insert(
                                                    "script".to_string(),
                                                    json!(script_arg.to_string()),
                                                );

                                                events.push(event_builders::event(
                                                    host,
                                                    "script_monitor",
                                                    "interpreter_exec_writable",
                                                    "medium",
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
            }
        }
    }

    events
}
