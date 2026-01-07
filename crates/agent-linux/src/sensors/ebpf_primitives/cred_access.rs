// linux/sensors/ebpf_primitives/cred_access.rs
// Detects credential access via bounded tool execution (ssh, gpg, pass, openssl, etc.)

use crate::core::event_keys;
use crate::core::Event;
use serde_json::json;
use std::collections::BTreeMap;

/// Detect credential access from exec events
/// Triggers on: ssh, ssh-add, ssh-keygen, gpg, pass, secret-tool, openssl, keyctl, security
pub fn detect_cred_access(base_event: &Event) -> Option<Event> {
    let cred_tools = [
        "ssh",
        "ssh-add",
        "ssh-keygen",
        "gpg",
        "pass",
        "secret-tool",
        "openssl",
        "keyctl",
        "security",
    ];

    // Extract exe from base exec event
    let exe = base_event
        .fields
        .get(event_keys::PROC_EXE)
        .and_then(|v| v.as_str())?;

    let exe_base = std::path::Path::new(exe).file_name()?.to_str()?;

    // Check if exe matches any cred tool
    let matched_tool = cred_tools.iter().find(|tool| exe_base.contains(**tool))?;

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
        event_keys::CRED_TOOL.to_string(),
        json!(matched_tool.to_string()),
    );

    if !argv.is_empty() {
        fields.insert(event_keys::PROC_ARGV.to_string(), json!(argv));
    }

    Some(Event {
        ts_ms: base_event.ts_ms,
        host: base_event.host.clone(),
        tags: vec![
            "linux".to_string(),
            "credential_access".to_string(),
            "ebpf".to_string(),
        ],
        proc_key: base_event.proc_key.clone(),
        file_key: None,
        identity_key: base_event.identity_key.clone(),
        evidence_ptr: None, // Capture will assign this
        fields,
    })
}
