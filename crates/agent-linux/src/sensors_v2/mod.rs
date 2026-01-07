//! Linux sensors v2 - contract-clean implementations
//! All sensors emit pure core::Event without side effects
//! EvidencePtr assigned by capture layer only
//! No telemetry, gnn, trust, or background threads

use crate::core::Event;
use crate::linux::event_builders;
use crate::linux::host::HostCtx;

pub mod common;
pub mod config;
pub mod metrics;
pub mod noise_policy;
pub mod semantic_audit;

// Real implementations
pub mod net_watch;
pub mod process_monitor;
pub mod procfs_process;

// Attack surface detection modules (Linux only)
#[cfg(target_os = "linux")]
pub mod attack_surface;
#[cfg(target_os = "linux")]
pub mod c2_detection;
#[cfg(target_os = "linux")]
pub mod defense_evasion;
#[cfg(target_os = "linux")]
pub mod lateral_movement;

// Implemented sensors (production-ready)
pub mod alert_engine;
pub mod auth_monitor;
pub mod auth_pipe_listener;
pub mod cloud_tracker;
pub mod container_monitor;
pub mod dll_injection_monitor;
pub mod encrypted_payload_detector;
pub mod entropy_exec_monitor;
pub mod file_hash_watcher;
pub mod file_tamper_monitor;
pub mod geo_ip_anomaly;
pub mod job_sched_monitor;
pub mod lkm_monitor;
pub mod logon_tracker;
pub mod mem_scan;
pub mod mfa_bypass;
pub mod password_spray;
pub mod persistence_watch;
pub mod privilege_monitor;
pub mod process_injection;
pub mod replay_writer;
pub mod script_monitor;
pub mod signal_integrity_mapper;
pub mod suspicious_ipc;
pub mod telemetry_fingerprint;
pub mod trust_state_restorer;
pub mod usb_monitor;
pub mod user_tracker;

/// Collect events from all available sensors with panic isolation and gating
pub fn collect_all(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Real implementations
    events.extend(safe_call("procfs_process", || {
        procfs_process::collect(host)
    }));
    events.extend(safe_call("process_monitor", || {
        process_monitor::collect(host)
    }));
    events.extend(safe_call("net_watch", || net_watch::collect(host)));

    // Implemented production sensors
    events.extend(safe_call("alert_engine", || alert_engine::collect(host)));
    events.extend(safe_call("auth_monitor", || auth_monitor::collect(host)));
    events.extend(safe_call("auth_pipe_listener", || {
        auth_pipe_listener::collect(host)
    }));
    events.extend(safe_call("cloud_tracker", || cloud_tracker::collect(host)));
    events.extend(safe_call("container_monitor", || {
        container_monitor::collect(host)
    }));
    events.extend(safe_call("dll_injection_monitor", || {
        dll_injection_monitor::collect(host)
    }));
    events.extend(safe_call("encrypted_payload_detector", || {
        encrypted_payload_detector::collect(host)
    }));
    events.extend(safe_call("entropy_exec_monitor", || {
        entropy_exec_monitor::collect(host)
    }));
    events.extend(safe_call("file_hash_watcher", || {
        file_hash_watcher::collect(host)
    }));
    events.extend(safe_call("file_tamper_monitor", || {
        file_tamper_monitor::collect(host)
    }));
    events.extend(safe_call("geo_ip_anomaly", || {
        geo_ip_anomaly::collect(host)
    }));
    events.extend(safe_call("job_sched_monitor", || {
        job_sched_monitor::collect(host)
    }));
    events.extend(safe_call("lkm_monitor", || lkm_monitor::collect(host)));
    events.extend(safe_call("logon_tracker", || logon_tracker::collect(host)));
    events.extend(safe_call("mem_scan", || mem_scan::collect(host)));
    events.extend(safe_call("mfa_bypass", || mfa_bypass::collect(host)));
    events.extend(safe_call("password_spray", || {
        password_spray::collect(host)
    }));
    events.extend(safe_call("persistence_watch", || {
        persistence_watch::collect(host)
    }));
    events.extend(safe_call("privilege_monitor", || {
        privilege_monitor::collect(host)
    }));
    events.extend(safe_call("process_injection", || {
        process_injection::collect(host)
    }));
    events.extend(safe_call("replay_writer", || replay_writer::collect(host)));
    events.extend(safe_call("script_monitor", || {
        script_monitor::collect(host)
    }));
    events.extend(safe_call("signal_integrity_mapper", || {
        signal_integrity_mapper::collect(host)
    }));
    events.extend(safe_call("suspicious_ipc", || {
        suspicious_ipc::collect(host)
    }));
    events.extend(safe_call("telemetry_fingerprint", || {
        telemetry_fingerprint::collect(host)
    }));
    events.extend(safe_call("trust_state_restorer", || {
        trust_state_restorer::collect(host)
    }));
    events.extend(safe_call("usb_monitor", || usb_monitor::collect(host)));
    events.extend(safe_call("user_tracker", || user_tracker::collect(host)));

    // Attack surface detection (privilege escalation, lateral movement, evasion)
    #[cfg(target_os = "linux")]
    {
        events.extend(safe_call("attack_surface_priv", || {
            attack_surface::collect_priv_escalation(host)
        }));
        events.extend(safe_call("attack_surface_net_tools", || {
            attack_surface::collect_remote_tool_exec(host)
        }));
    }

    // Sort deterministically for reproducible output
    sort_events(&mut events);

    events
}

/// Call a sensor with panic isolation
fn safe_call<F>(sensor_name: &str, f: F) -> Vec<Event>
where
    F: FnOnce() -> Vec<Event> + std::panic::UnwindSafe,
{
    let (should_run, cfg) = config::should_poll(sensor_name);

    if !should_run {
        return Vec::new();
    }

    let host = HostCtx::new();
    let result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(mut events) => {
            // Cap events to configured max
            if events.len() > cfg.max_events_per_poll {
                events.truncate(cfg.max_events_per_poll);
            }
            events
        }
        Err(_) => vec![event_builders::sensor_failure(
            &host,
            sensor_name,
            "panic in collect()",
        )],
    };

    result
}

/// Sort events deterministically by kind, pid, path, remote_ip, then ts_ms
/// This ensures identical inputs produce identical event order in output
fn sort_events(events: &mut Vec<Event>) {
    events.sort_by(|a, b| {
        // 1. Sort by kind (first tag, or empty string)
        let kind_a = a.tags.first().cloned().unwrap_or_default();
        let kind_b = b.tags.first().cloned().unwrap_or_default();
        match kind_a.cmp(&kind_b) {
            std::cmp::Ordering::Equal => {
                // 2. Sort by pid (PROC_PID field if present)
                let pid_a = a
                    .fields
                    .get(crate::core::event_keys::PROC_PID)
                    .and_then(|v| v.as_i64())
                    .unwrap_or(i64::MAX);
                let pid_b = b
                    .fields
                    .get(crate::core::event_keys::PROC_PID)
                    .and_then(|v| v.as_i64())
                    .unwrap_or(i64::MAX);
                match pid_a.cmp(&pid_b) {
                    std::cmp::Ordering::Equal => {
                        // 3. Sort by path (FILE_PATH field if present)
                        let path_a = a
                            .fields
                            .get(crate::core::event_keys::FILE_PATH)
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let path_b = b
                            .fields
                            .get(crate::core::event_keys::FILE_PATH)
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        match path_a.cmp(path_b) {
                            std::cmp::Ordering::Equal => {
                                // 4. Sort by remote_ip (NET_REMOTE_IP field if present)
                                let ip_a = a
                                    .fields
                                    .get(crate::core::event_keys::NET_REMOTE_IP)
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");
                                let ip_b = b
                                    .fields
                                    .get(crate::core::event_keys::NET_REMOTE_IP)
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");
                                match ip_a.cmp(ip_b) {
                                    std::cmp::Ordering::Equal => {
                                        // 5. Finally sort by ts_ms (last resort)
                                        a.ts_ms.cmp(&b.ts_ms)
                                    }
                                    other => other,
                                }
                            }
                            other => other,
                        }
                    }
                    other => other,
                }
            }
            other => other,
        }
    });
}
