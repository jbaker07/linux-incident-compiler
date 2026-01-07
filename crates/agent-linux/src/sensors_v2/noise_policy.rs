//! Noise budget and rate-limit policy for sensors
//! Prevents sensor spam while preserving critical alerts

/// Per-sensor noise budget
pub struct SensorPolicy {
    pub max_events_per_poll: usize,
    pub severity_bypass: bool, // Critical events bypass budget
}

/// Global noise policies
pub fn get_policy(sensor_name: &str) -> SensorPolicy {
    match sensor_name {
        "alert_engine" => SensorPolicy {
            max_events_per_poll: 100,
            severity_bypass: true,
        },
        "auth_monitor" => SensorPolicy {
            max_events_per_poll: 50,
            severity_bypass: true,
        },
        "auth_pipe_listener" => SensorPolicy {
            max_events_per_poll: 30,
            severity_bypass: true,
        },
        "cloud_tracker" => SensorPolicy {
            max_events_per_poll: 20,
            severity_bypass: false,
        },
        "container_monitor" => SensorPolicy {
            max_events_per_poll: 40,
            severity_bypass: false,
        },
        "dll_injection_monitor" => SensorPolicy {
            max_events_per_poll: 50,
            severity_bypass: true,
        },
        "encrypted_payload_detector" => SensorPolicy {
            max_events_per_poll: 30,
            severity_bypass: false,
        },
        "entropy_exec_monitor" => SensorPolicy {
            max_events_per_poll: 25,
            severity_bypass: true,
        },
        "file_hash_watcher" => SensorPolicy {
            max_events_per_poll: 20,
            severity_bypass: true,
        },
        "file_tamper_monitor" => SensorPolicy {
            max_events_per_poll: 30,
            severity_bypass: false,
        },
        "geo_ip_anomaly" => SensorPolicy {
            max_events_per_poll: 40,
            severity_bypass: true,
        },
        "job_sched_monitor" => SensorPolicy {
            max_events_per_poll: 15,
            severity_bypass: false,
        },
        "lkm_monitor" => SensorPolicy {
            max_events_per_poll: 50,
            severity_bypass: true,
        },
        "logon_tracker" => SensorPolicy {
            max_events_per_poll: 60,
            severity_bypass: true,
        },
        "mem_scan" => SensorPolicy {
            max_events_per_poll: 50,
            severity_bypass: true,
        },
        "mfa_bypass" => SensorPolicy {
            max_events_per_poll: 30,
            severity_bypass: true,
        },
        "password_spray" => SensorPolicy {
            max_events_per_poll: 40,
            severity_bypass: true,
        },
        "persistence_watch" => SensorPolicy {
            max_events_per_poll: 20,
            severity_bypass: false,
        },
        "privilege_monitor" => SensorPolicy {
            max_events_per_poll: 35,
            severity_bypass: true,
        },
        "process_injection" => SensorPolicy {
            max_events_per_poll: 50,
            severity_bypass: true,
        },
        "replay_writer" => SensorPolicy {
            max_events_per_poll: 100,
            severity_bypass: false,
        },
        "script_monitor" => SensorPolicy {
            max_events_per_poll: 25,
            severity_bypass: false,
        },
        "signal_integrity_mapper" => SensorPolicy {
            max_events_per_poll: 30,
            severity_bypass: false,
        },
        "suspicious_ipc" => SensorPolicy {
            max_events_per_poll: 40,
            severity_bypass: true,
        },
        "telemetry_fingerprint" => SensorPolicy {
            max_events_per_poll: 50,
            severity_bypass: false,
        },
        "trust_state_restorer" => SensorPolicy {
            max_events_per_poll: 20,
            severity_bypass: false,
        },
        "usb_monitor" => SensorPolicy {
            max_events_per_poll: 15,
            severity_bypass: true,
        },
        "user_tracker" => SensorPolicy {
            max_events_per_poll: 30,
            severity_bypass: false,
        },
        "procfs_process" => SensorPolicy {
            max_events_per_poll: 200,
            severity_bypass: false,
        },
        "process_monitor" => SensorPolicy {
            max_events_per_poll: 100,
            severity_bypass: false,
        },
        "net_watch" => SensorPolicy {
            max_events_per_poll: 100,
            severity_bypass: false,
        },
        _ => SensorPolicy {
            max_events_per_poll: 50,
            severity_bypass: false,
        },
    }
}

/// Apply noise budget to events: cap at max, separate by severity
pub fn apply_budget(
    sensor_name: &str,
    events: Vec<crate::core::Event>,
) -> (Vec<crate::core::Event>, bool) {
    let policy = get_policy(sensor_name);

    // Separate critical from normal
    let mut critical = Vec::new();
    let mut normal = Vec::new();

    for event in events {
        let severity = event
            .tags
            .iter()
            .find(|tag| {
                matches!(
                    tag.as_str(),
                    "critical" | "high" | "medium" | "low" | "info"
                )
            })
            .cloned()
            .unwrap_or_default();

        if severity == "critical" && policy.severity_bypass {
            critical.push(event);
        } else {
            normal.push(event);
        }
    }

    let was_capped = normal.len() > policy.max_events_per_poll;

    // Keep all critical, cap normal
    critical.extend(normal.into_iter().take(policy.max_events_per_poll));

    (critical, was_capped)
}
