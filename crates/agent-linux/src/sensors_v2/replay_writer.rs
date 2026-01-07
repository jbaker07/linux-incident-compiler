//! replay_writer sensor v2
//! NO FILE WRITES. Convert into "demo event injector" gated by env var EDR_DEMO=1

use crate::core::Event;
use crate::linux::event_builders;
use crate::linux::host::HostCtx;
use serde_json::json;
use std::collections::BTreeMap;

/// Collect replay_writer events - demo injector, no file writes
pub fn collect(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Check 1: High-precision invariant - detect if demo mode is enabled
    if let Ok(demo_enabled) = std::env::var("EDR_DEMO") {
        if demo_enabled == "1" || demo_enabled == "true" {
            // Emit synthetic demo events for testing/visualization
            events.extend(generate_demo_events(host));
        }
    }

    // No file writes - this sensor is strictly read-only for demo purposes
    events
}

/// Generate synthetic demo events for visualization/testing
fn generate_demo_events(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Only emit once per session
    if !super::common::rate_limit("replay_writer", "demo_init", 3600000) {
        return events;
    }

    // Demo event 1: Suspicious process execution
    let mut fields1 = BTreeMap::new();
    fields1.insert("pid".to_string(), json!(99999));
    fields1.insert("exe".to_string(), json!("/tmp/demo_exploit"));
    fields1.insert("parent_exe".to_string(), json!("/bin/bash"));
    fields1.insert("reason".to_string(), json!("demo: exec from /tmp"));

    events.push(event_builders::event(
        host,
        "replay_writer",
        "demo_event",
        "info",
        fields1,
    ));

    // Demo event 2: Network anomaly
    let mut fields2 = BTreeMap::new();
    fields2.insert("remote_ip".to_string(), json!("1.2.3.4"));
    fields2.insert("port".to_string(), json!(4444));
    fields2.insert("reason".to_string(), json!("demo: C2 connection"));

    events.push(event_builders::event(
        host,
        "replay_writer",
        "demo_event",
        "info",
        fields2,
    ));

    // Demo event 3: Privilege escalation attempt
    let mut fields3 = BTreeMap::new();
    fields3.insert("user".to_string(), json!("attacker"));
    fields3.insert("target_uid".to_string(), json!(0));
    fields3.insert("reason".to_string(), json!("demo: privilege escalation"));

    events.push(event_builders::event(
        host,
        "replay_writer",
        "demo_event",
        "info",
        fields3,
    ));

    events
}
