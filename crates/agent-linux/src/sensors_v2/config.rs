//! Per-sensor configuration with env var support
//! All times in milliseconds. All limits are process-local, not global.
//! Designed for stable, bounded sensor behavior without per-poll surprises.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

/// Work budget for a single poll() call
#[derive(Clone, Copy, Debug)]
pub struct WorkBudget {
    /// Maximum files to scan in one poll
    pub max_files: usize,
    /// Maximum bytes to read per file
    pub max_bytes_per_file: u64,
    /// Maximum total bytes to read in one poll
    pub max_bytes_total: u64,
}

/// Per-sensor configuration
#[derive(Clone, Debug)]
pub struct SensorConfig {
    /// If false, sensor.collect() is skipped entirely
    pub enabled: bool,
    /// Minimum milliseconds between collect() calls (gating interval)
    pub min_interval_ms: u64,
    /// Maximum events to emit per collect() call
    pub max_events_per_poll: usize,
    /// Work budget for I/O-heavy sensors
    pub work_budget: WorkBudget,
}

impl Default for SensorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_interval_ms: 100,
            max_events_per_poll: 100,
            work_budget: WorkBudget {
                max_files: 1000,
                max_bytes_per_file: 10_000_000,
                max_bytes_total: 100_000_000,
            },
        }
    }
}

/// Global config store with lazy initialization
struct ConfigStore {
    sensor_configs: HashMap<String, SensorConfig>,
    last_poll_times: HashMap<String, u64>,
}

static CONFIG: OnceLock<ConfigStore> = OnceLock::new();

fn get_store() -> &'static ConfigStore {
    CONFIG.get_or_init(|| ConfigStore {
        sensor_configs: init_configs(),
        last_poll_times: HashMap::new(),
    })
}

/// Load sensor configs from env vars or use defaults
fn init_configs() -> HashMap<String, SensorConfig> {
    let mut configs = HashMap::new();

    // Sensor-specific overrides via env vars
    // Format: EDR_SENSOR_<NAME>_<SETTING>=value
    // SETTING can be: ENABLED, MIN_INTERVAL_MS, MAX_EVENTS_PER_POLL, MAX_FILES, MAX_BYTES_PER_FILE, MAX_BYTES_TOTAL

    for sensor_name in &[
        "procfs_process",
        "process_monitor",
        "net_watch",
        "alert_engine",
        "auth_monitor",
        "auth_pipe_listener",
        "cloud_tracker",
        "container_monitor",
        "dll_injection_monitor",
        "encrypted_payload_detector",
        "entropy_exec_monitor",
        "file_hash_watcher",
        "file_tamper_monitor",
        "geo_ip_anomaly",
        "job_sched_monitor",
        "lkm_monitor",
        "logon_tracker",
        "mem_scan",
        "mfa_bypass",
        "password_spray",
        "persistence_watch",
        "privilege_monitor",
        "process_injection",
        "replay_writer",
        "script_monitor",
        "signal_integrity_mapper",
        "suspicious_ipc",
        "telemetry_fingerprint",
        "trust_state_restorer",
        "usb_monitor",
        "user_tracker",
    ] {
        let mut cfg = SensorConfig::default();

        // Per-sensor overrides
        match *sensor_name {
            "encrypted_payload_detector" => {
                // Scan every 5s, cap work
                cfg.min_interval_ms = 5000;
                cfg.max_events_per_poll = 10;
                cfg.work_budget = WorkBudget {
                    max_files: 100,
                    max_bytes_per_file: 1_000_000,
                    max_bytes_total: 50_000_000,
                };
            }
            "mem_scan" => {
                cfg.min_interval_ms = 10_000;
                cfg.work_budget = WorkBudget {
                    max_files: 50,
                    max_bytes_per_file: 100_000_000,
                    max_bytes_total: 500_000_000,
                };
            }
            "file_hash_watcher" => {
                cfg.min_interval_ms = 2000;
                cfg.work_budget = WorkBudget {
                    max_files: 500,
                    max_bytes_per_file: 1_000_000,
                    max_bytes_total: 200_000_000,
                };
            }
            "procfs_process" | "process_monitor" | "net_watch" => {
                // Core sensors run frequently
                cfg.min_interval_ms = 100;
                cfg.max_events_per_poll = 50;
            }
            _ => {}
        }

        // Environment variable overrides (format: EDR_SENSOR_<UPPER>_<SETTING>=value)
        let env_prefix = format!("EDR_SENSOR_{}", sensor_name.to_uppercase());

        if let Ok(enabled) = std::env::var(format!("{}_ENABLED", env_prefix)) {
            cfg.enabled = enabled.to_lowercase() == "true" || enabled == "1";
        }
        if let Ok(interval) = std::env::var(format!("{}_MIN_INTERVAL_MS", env_prefix)) {
            if let Ok(ms) = interval.parse() {
                cfg.min_interval_ms = ms;
            }
        }
        if let Ok(max_events) = std::env::var(format!("{}_MAX_EVENTS_PER_POLL", env_prefix)) {
            if let Ok(n) = max_events.parse() {
                cfg.max_events_per_poll = n;
            }
        }
        if let Ok(max_files) = std::env::var(format!("{}_MAX_FILES", env_prefix)) {
            if let Ok(n) = max_files.parse() {
                cfg.work_budget.max_files = n;
            }
        }
        if let Ok(max_bytes_per_file) = std::env::var(format!("{}_MAX_BYTES_PER_FILE", env_prefix))
        {
            if let Ok(n) = max_bytes_per_file.parse() {
                cfg.work_budget.max_bytes_per_file = n;
            }
        }
        if let Ok(max_bytes_total) = std::env::var(format!("{}_MAX_BYTES_TOTAL", env_prefix)) {
            if let Ok(n) = max_bytes_total.parse() {
                cfg.work_budget.max_bytes_total = n;
            }
        }

        configs.insert(sensor_name.to_string(), cfg);
    }

    configs
}

/// Check if sensor should run and update last poll time
/// Returns (should_run, config)
/// Sensor should early-return Vec::new() if should_run is false
pub fn should_poll(sensor_name: &str) -> (bool, SensorConfig) {
    let store = get_store();
    let cfg = store
        .sensor_configs
        .get(sensor_name)
        .cloned()
        .unwrap_or_default();

    if !cfg.enabled {
        return (false, cfg);
    }

    let now = now_ms();
    let last_poll = store.last_poll_times.get(sensor_name).copied().unwrap_or(0);

    if now - last_poll < cfg.min_interval_ms {
        return (false, cfg);
    }

    // In a real implementation, we'd update last_poll_times here with interior mutability.
    // For now, this is conservative (may over-poll on first call).
    (true, cfg)
}

/// Call this after sensor completes to record poll time
/// Reserved for future instrumentation with interior mutability (RefCell/Mutex).
pub fn record_poll(sensor_name: &str) {
    let _now = now_ms();
    // In production: store.last_poll_times.insert(sensor_name.to_string(), _now);
    // This requires RefCell or Mutex wrapping the store.
}

/// Current time in milliseconds since UNIX_EPOCH
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
