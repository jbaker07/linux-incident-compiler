//! Linux lateral movement detection primitives
//! Network connections and remote tool execution

use crate::core::{event_keys, Event};
use crate::linux::event_builders;
use crate::linux::host::HostCtx;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::net::IpAddr;

/// DEPRECATED: Use linux::sensors::ebpf_primitives::net_connect instead
/// This function is superseded by the canonical network_connection primitive
/// which provides consistent field naming and tagging across all platforms.
///
/// Legacy network connection detection from eBPF tcp_connect stream
/// NOTE: This is no longer called and should not be used for new code
#[deprecated(since = "1.2.0", note = "Use ebpf_primitives::net_connect instead")]
pub fn collect_net_connect(host: &HostCtx, ebpf_events: &[crate::core::Event]) -> Vec<Event> {
    let mut events = Vec::new();

    // Filter eBPF events that indicate tcp_connect
    // Expected: events with tags containing "network" and "connect"
    for ebpf_evt in ebpf_events {
        if !ebpf_evt.tag_contains("network") || !ebpf_evt.tag_contains("connect") {
            continue;
        }

        // Extract needed fields from eBPF event
        let pid = ebpf_evt
            .fields
            .get(event_keys::PROC_PID)
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        let uid = ebpf_evt
            .fields
            .get(event_keys::PROC_UID)
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        let exe = ebpf_evt
            .fields
            .get(event_keys::PROC_EXE)
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let comm = ebpf_evt
            .fields
            .get(event_keys::PROC_COMM)
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let remote_ip = ebpf_evt
            .fields
            .get(event_keys::NET_REMOTE_IP)
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0.0")
            .to_string();

        let remote_port = ebpf_evt
            .fields
            .get(event_keys::NET_REMOTE_PORT)
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u16;

        let family = ebpf_evt
            .fields
            .get(event_keys::NET_PROTO)
            .and_then(|v| v.as_str())
            .unwrap_or("ipv4")
            .to_string();

        // Determine if private/link-local
        let is_private = is_private_ip(&remote_ip);
        let is_link_local = is_link_local_ip(&remote_ip);

        let mut fields = BTreeMap::new();
        fields.insert(event_keys::PROC_PID.to_string(), json!(pid));
        fields.insert(event_keys::PROC_UID.to_string(), json!(uid));
        fields.insert(event_keys::PROC_EXE.to_string(), json!(exe));
        fields.insert(event_keys::PROC_COMM.to_string(), json!(comm));
        fields.insert(event_keys::NET_REMOTE_IP.to_string(), json!(remote_ip));
        fields.insert(event_keys::NET_REMOTE_PORT.to_string(), json!(remote_port));
        fields.insert("family".to_string(), json!(family));
        fields.insert("is_private_ip".to_string(), json!(is_private));
        fields.insert("is_link_local".to_string(), json!(is_link_local));

        let mut ev = event_builders::event(host, "attack_surface", "net_connect", "info", fields);
        ev.tags
            .extend(vec!["network".to_string(), "connect".to_string()]);
        events.push(ev);
    }

    events
}

/// Check if IP is in private range (RFC1918 or loopback)
fn is_private_ip(ip_str: &str) -> bool {
    if let Ok(ip) = ip_str.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
            IpAddr::V6(v6) => v6.is_loopback() || v6.is_link_local() || v6.is_unique_local(),
        }
    } else {
        false
    }
}

/// Check if IP is link-local (169.254.x.x or fe80::/10)
fn is_link_local_ip(ip_str: &str) -> bool {
    if let Ok(ip) = ip_str.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => v4.is_link_local(),
            IpAddr::V6(v6) => v6.is_link_local(),
        }
    } else {
        false
    }
}
