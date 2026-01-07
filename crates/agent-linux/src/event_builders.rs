//! Canonical event builders for Linux sensors
//! Ensures consistent Event structure across all sensor implementations

use crate::core::{event_keys, Event};
use crate::linux::host::HostCtx;
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// Build a canonical sensor event
pub fn event(
    host_ctx: &HostCtx,
    sensor_name: &str,
    kind: &str,
    severity: &str,
    mut fields: BTreeMap<String, Value>,
) -> Event {
    fields
        .entry("sensor".to_string())
        .or_insert_with(|| json!(sensor_name));
    fields
        .entry("kind".to_string())
        .or_insert_with(|| json!(kind));
    fields
        .entry("severity".to_string())
        .or_insert_with(|| json!(severity));

    Event {
        ts_ms: host_ctx.now_ms(),
        host: host_ctx.hostname.clone(),
        tags: vec![
            "linux".to_string(),
            kind.to_string(),
            sensor_name.to_string(),
        ],
        proc_key: None,
        file_key: None,
        identity_key: None,
        // EvidencePtr assigned by capture writer only
        evidence_ptr: None,
        fields,
    }
}

/// Build a sensor failure/error event
pub fn sensor_failure(host_ctx: &HostCtx, module: &str, error: &str) -> Event {
    let mut fields = BTreeMap::new();
    fields.insert("error".to_string(), json!(error));

    event(host_ctx, module, "sensor_error", "warn", fields)
}

/// Quick builder for process events
pub fn process_event(
    host_ctx: &HostCtx,
    sensor_name: &str,
    pid: u32,
    ppid: u32,
    exe: &str,
    extra_fields: BTreeMap<String, Value>,
) -> Event {
    let mut fields = extra_fields;
    fields.insert("pid".to_string(), json!(pid));
    fields.insert("ppid".to_string(), json!(ppid));
    fields.insert("exe".to_string(), json!(exe));

    event(host_ctx, sensor_name, "process", "info", fields)
}

/// Quick builder for network events
pub fn network_event(
    host_ctx: &HostCtx,
    sensor_name: &str,
    src_ip: &str,
    dst_ip: &str,
    port: u16,
    extra_fields: BTreeMap<String, Value>,
) -> Event {
    let mut fields = extra_fields;
    fields.insert("src_ip".to_string(), json!(src_ip));
    fields.insert(event_keys::NET_REMOTE_IP.to_string(), json!(dst_ip));
    fields.insert(event_keys::NET_REMOTE_PORT.to_string(), json!(port));

    event(host_ctx, sensor_name, "network", "info", fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_event_uses_canonical_field_keys() {
        // Verify that network_event uses canonical event_keys constants for remote IP/port
        let host = HostCtx::new();
        let mut extra_fields = BTreeMap::new();
        extra_fields.insert("extra".to_string(), json!("value"));

        let ev = network_event(
            &host,
            "test_sensor",
            "192.168.1.100",
            "8.8.8.8",
            443,
            extra_fields,
        );

        // CRITICAL: Fields must use canonical event_keys constants (remote_ip, remote_port)
        assert!(
            ev.fields.contains_key(event_keys::NET_REMOTE_IP),
            "Event must contain key '{}' (canonical NET_REMOTE_IP constant)",
            event_keys::NET_REMOTE_IP
        );
        assert!(
            ev.fields.contains_key(event_keys::NET_REMOTE_PORT),
            "Event must contain key '{}' (canonical NET_REMOTE_PORT constant)",
            event_keys::NET_REMOTE_PORT
        );

        // Verify values are correct
        assert_eq!(
            ev.fields
                .get(event_keys::NET_REMOTE_IP)
                .and_then(|v| v.as_str()),
            Some("8.8.8.8"),
            "remote_ip field value mismatch"
        );
        assert_eq!(
            ev.fields
                .get(event_keys::NET_REMOTE_PORT)
                .and_then(|v| v.as_u64()),
            Some(443),
            "remote_port field value mismatch"
        );
    }
}
