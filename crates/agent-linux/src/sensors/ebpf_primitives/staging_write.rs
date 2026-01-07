// linux/sensors/ebpf_primitives/staging_write.rs
// Detects file writes to staging directories (/tmp, /var/tmp, /dev/shm, ~/Downloads, ~/Desktop, ~/.cache)

use crate::core::event_keys;
use crate::core::Event;
use serde_json::json;
use std::collections::BTreeMap;

/// Detect writes to staging directories
/// Triggers on paths matching:
/// - /tmp/, /var/tmp/, /dev/shm/ (temporary staging)
/// - /home/*/Downloads/ (download staging)
/// - /home/*/Desktop/ (user desktop staging)
/// - ~/.cache/ (cache staging)
pub fn detect_staging_write(base_event: &Event) -> Option<Event> {
    let staging_prefixes = [
        "/tmp/",
        "/var/tmp/",
        "/dev/shm/",
        "/home/", // Will check for Downloads/ or Desktop/ or .cache/ suffix
    ];

    // Extract path from base file op event
    let path = base_event
        .fields
        .get(event_keys::FILE_PATH)
        .and_then(|v| v.as_str())?;

    // Check if path matches staging directories
    let mut is_staging = false;
    for prefix in &staging_prefixes {
        if path.starts_with(prefix) {
            if *prefix == "/home/" {
                // Check if it contains Downloads, Desktop, or .cache
                if path.contains("/Downloads/")
                    || path.contains("/Desktop/")
                    || path.contains("/.cache/")
                {
                    is_staging = true;
                }
            } else {
                is_staging = true;
            }
            if is_staging {
                break;
            }
        }
    }

    if !is_staging {
        return None;
    }

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

    let exe = base_event
        .fields
        .get(event_keys::PROC_EXE)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Determine operation type
    let op = base_event
        .fields
        .get(event_keys::FILE_OP)
        .and_then(|v| v.as_str())
        .unwrap_or("write")
        .to_string();

    let mut fields = BTreeMap::new();
    fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
    fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
    fields.insert(event_keys::PROC_EUID.to_string(), json!(euid));
    if !exe.is_empty() {
        fields.insert(event_keys::PROC_EXE.to_string(), json!(exe));
    }
    fields.insert(event_keys::FILE_PATH.to_string(), json!(path));
    fields.insert(event_keys::FILE_OP.to_string(), json!(op));
    fields.insert(
        event_keys::PRIMITIVE_SUBTYPE.to_string(),
        json!("staging_write"),
    ); // Distinguish from archive_tool_exec

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
