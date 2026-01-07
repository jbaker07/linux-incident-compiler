//! Sensor semantic audit: kinds vs. actual behavior
//! Maps sensor -> emitted kinds -> data sources -> confidence level

/*
SENSOR_AUDIT_TABLE:
alert_engine: alert_candidate, episode_candidate
auth_monitor: failed_login, brute_force
(Full audit below)
*/

/// Semantic correctness audit: sensor name vs. what it actually detects
pub fn audit_semantic_correctness() -> &'static str {
    "SEMANTIC_AUDIT_TABLE

    Sensor Name              | Actual Kinds Emitted              | Data Sources                    | Confidence | Status
    =====================================================================================================================================
    alert_engine             | alert_candidate, episode_candidate| event buffer bursts            | high       | ✓ Correct
    auth_monitor             | failed_login, brute_force         | /var/log/auth.log              | high       | ✓ Correct
    auth_pipe_listener       | suspicious_auth_pipe              | PAM FIFO inspection            | medium     | ✓ Correct
    cloud_tracker            | cloud_cli_activity                | cloud config dirs              | medium     | ✓ Correct
    container_monitor        | container_socket_access           | docker socket, cgroup          | high       | ✓ Correct
    dll_injection_monitor    | dll_injection, rwx_anon           | LD_PRELOAD, /proc/maps         | high       | ✓ Correct (Linux-only)
    encrypted_payload_...    | entropy_anomaly                   | /tmp entropy calc              | medium     | ✓ Correct (High FP rate)
    entropy_exec_monitor     | entropy_execution                 | cmdline argument entropy       | medium     | ✓ Correct
    file_hash_watcher        | file_modified                     | SHA256 of core binaries        | high       | ✓ Correct
    file_tamper_monitor      | file_tamper                       | /etc/passwd, /etc/shadow       | high       | ✓ Correct
    geo_ip_anomaly           | geo_anomaly                       | (disabled by default)          | low        | ⚠ Disabled
    job_sched_monitor        | suspicious_cron, suspicious_...   | /etc/cron.*, systemd units     | high       | ✓ Correct
    lkm_monitor              | kernel_module_loaded              | /proc/modules                  | high       | ✓ Correct
    logon_tracker            | user_logon                        | /var/log/wtmp                  | medium     | ✓ Correct
    mem_scan                 | rwx_memory, wx_transition, ...    | /proc/*/maps permissions       | high       | ⚠ W->X may miss gaps
    mfa_bypass               | mfa_bypass_attempt                | auth.log pattern match         | low        | ✓ Heuristic
    password_spray           | password_spray_detected           | /var/log/auth.log frequency    | high       | ✓ Correct
    persistence_watch        | persistence_artifact              | ~/.bashrc, ~/.ssh, etc         | high       | ✓ Correct
    privilege_monitor        | privilege_change                  | /etc/sudoers validation        | medium     | ✗ MISNAMED: Should be file_tamper
    process_injection        | process_injection                 | tracer_pid, RWX regions        | high       | ✓ Correct
    replay_writer            | replay_record                     | event buffer playback          | low        | ✓ Observability only
    script_monitor           | script_execution                  | process cmdline, interpreters  | medium     | ✓ Correct
    signal_integrity_...     | signal_integrity                  | (stubbed, no validation)       | low        | ⚠ Placeholder
    suspicious_ipc           | suspicious_ipc                    | /proc/net/unix, /dev/shm       | medium     | ✓ Correct
    telemetry_fingerprint    | telemetry_fingerprint             | host metadata                  | high       | ✓ Observability only
    trust_state_restorer     | trust_state                       | (stubbed)                      | low        | ⚠ Placeholder
    usb_monitor              | usb_device_inserted, risky_...    | /sys/bus/usb/devices sysfs    | high       | ✓ Correct
    user_tracker             | user_login, user_activity         | auth.log, /proc status         | medium     | ✓ Correct

    ISSUES FOUND:
    1. privilege_monitor: Name suggests privilege escalation detection (uid transitions, setuid),
       but actually monitors /etc/sudoers integrity (file tamper).
       FIX: Rename to 'sudoers_tamper_monitor' OR implement true privilege monitoring (uid/cap/setuid changes).

    2. mem_scan (W->X transition): May not detect temporal gaps between write and execute.
       NAME: Keep as-is. Add caveat in description.

    3. geo_ip_anomaly: Disabled by default; no actual geo lookup.
       NAME: Keep. Feature flag is documented.

    4. signal_integrity_mapper, trust_state_restorer: Placeholder stubs with no real validation.
       STATUS: Mark as observability stubs; consider removing or implementing fully.
"
}
