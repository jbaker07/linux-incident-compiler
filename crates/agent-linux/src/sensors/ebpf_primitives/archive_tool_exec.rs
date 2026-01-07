// linux/sensors/ebpf_primitives/archive_tool_exec.rs
// Detects archive/compression tool execution (tar, zip, gzip, xz, 7z, etc.)

use crate::core::event_keys;
use crate::core::Event;
use serde_json::json;
use std::collections::BTreeMap;

/// Detect archive tool execution from exec events
/// Triggers on: tar, zip, unzip, gzip, bzip2, xz, 7z
pub fn detect_archive_tool_exec(base_event: &Event) -> Option<Event> {
    let archive_tools = ["tar", "zip", "unzip", "gzip", "bzip2", "xz", "7z"];

    // Extract exe from base exec event
    let exe = base_event
        .fields
        .get(event_keys::PROC_EXE)
        .and_then(|v| v.as_str())?;

    let exe_base = std::path::Path::new(exe).file_name()?.to_str()?;

    // Check if exe matches any archive tool
    let matched_tool = archive_tools
        .iter()
        .find(|tool| exe_base.contains(**tool))?;

    // Extract required fields
    let pid = base_event
        .fields
        .get(event_keys::PROC_PID)
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)?;
    let uid = base_event
        .fields
        .get(event_keys::PROC_UID)
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)?;
    let euid = base_event
        .fields
        .get(event_keys::PROC_EUID)
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .unwrap_or(uid);

    let argv = base_event
        .fields
        .get(event_keys::PROC_ARGV)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(euid));
    fields.insert(event_keys::PROC_EXE.to_string(), json!(exe));
    fields.insert(
        event_keys::ARCHIVE_TOOL.to_string(),
        json!(matched_tool.to_string()),
    );
    fields.insert(
        event_keys::PRIMITIVE_SUBTYPE.to_string(),
        json!("archive_tool_exec"),
    ); // Distinguish from staging_write

    if !argv.is_empty() {
        fields.insert(event_keys::PROC_ARGV.to_string(), json!(argv));
    }

    Some(Event {
        ts_ms: base_event.ts_ms,
        host: base_event.host.clone(),
        tags: vec![
            "linux".to_string(),
            "exfiltration".to_string(),
            "ebpf".to_string(),
        ],
        proc_key: base_event.proc_key.clone(),
        file_key: None,
        identity_key: base_event.identity_key.clone(),
        evidence_ptr: None, // Capture will assign this
        fields,
    })
}
