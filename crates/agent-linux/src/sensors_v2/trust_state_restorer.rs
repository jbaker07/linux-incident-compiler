//! trust_state_restorer sensor v2
//! Emit one sensor_health summary of what state is present (in-memory)

use crate::core::Event;
use crate::linux::event_builders;
use crate::linux::host::HostCtx;
use serde_json::json;
use std::collections::BTreeMap;

/// Collect trust_state_restorer events - summary of system trust state
pub fn collect(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Collect system trust indicators
    let trust_state = gather_trust_state(host);

    // Emit one summary event (rate-limited to prevent spam)
    if super::common::rate_limit("trust_state_restorer", "summary", 3600000) {
        let mut fields = BTreeMap::new();
        fields.insert(
            "secure_boot_enabled".to_string(),
            json!(trust_state.secure_boot),
        );
        fields.insert("selinux_enabled".to_string(), json!(trust_state.selinux));
        fields.insert("apparmor_enabled".to_string(), json!(trust_state.apparmor));
        fields.insert("immu_enabled".to_string(), json!(trust_state.immu));
        fields.insert(
            "trusted_boot_capable".to_string(),
            json!(trust_state.trusted_boot),
        );
        fields.insert(
            "kernel_locked_down".to_string(),
            json!(trust_state.lockdown),
        );
        fields.insert(
            "module_signature_required".to_string(),
            json!(trust_state.module_sig_enforce),
        );
        fields.insert(
            "kexec_disabled".to_string(),
            json!(trust_state.kexec_disabled),
        );

        events.push(event_builders::event(
            host,
            "trust_state_restorer",
            "sensor_health",
            "info",
            fields,
        ));
    }

    events
}

/// Trust state information
struct TrustState {
    secure_boot: bool,
    selinux: bool,
    apparmor: bool,
    immu: bool,
    trusted_boot: bool,
    lockdown: bool,
    module_sig_enforce: bool,
    kexec_disabled: bool,
}

/// Gather system trust state from various sources
fn gather_trust_state(_host: &HostCtx) -> TrustState {
    TrustState {
        secure_boot: check_secure_boot(),
        selinux: check_selinux(),
        apparmor: check_apparmor(),
        immu: check_immu(),
        trusted_boot: check_trusted_boot(),
        lockdown: check_kernel_lockdown(),
        module_sig_enforce: check_module_signature_requirement(),
        kexec_disabled: check_kexec_disabled(),
    }
}

/// Check if Secure Boot is enabled
fn check_secure_boot() -> bool {
    std::fs::read_to_string("/sys/firmware/efi/efivars/SecureBoot-*")
        .ok()
        .map(|_| true)
        .unwrap_or(false)
}

/// Check if SELinux is enabled
fn check_selinux() -> bool {
    std::fs::read_to_string("/sys/fs/selinux/enforce")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .map(|v| v == 1)
        .unwrap_or(false)
}

/// Check if AppArmor is enabled
fn check_apparmor() -> bool {
    std::fs::read_to_string("/sys/module/apparmor/parameters/enabled")
        .ok()
        .map(|s| s.trim() == "Y")
        .unwrap_or(false)
}

/// Check if IMA (Integrity Measurement Architecture) is enabled
fn check_immu() -> bool {
    std::fs::read_to_string("/sys/kernel/security/ima/measure")
        .ok()
        .map(|_| true)
        .unwrap_or(false)
}

/// Check if Trusted Boot is capable
fn check_trusted_boot() -> bool {
    std::fs::metadata("/sys/firmware/efi/vars")
        .ok()
        .map(|m| m.is_dir())
        .unwrap_or(false)
}

/// Check if kernel lockdown is enabled
fn check_kernel_lockdown() -> bool {
    std::fs::read_to_string("/sys/kernel/security/lockdown")
        .ok()
        .map(|s| s.trim() != "none")
        .unwrap_or(false)
}

/// Check if module signature enforcement is enabled
fn check_module_signature_requirement() -> bool {
    std::fs::read_to_string("/sys/module/module/parameters/sig_enforce")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .map(|v| v == 1)
        .unwrap_or(false)
}

/// Check if kexec is disabled
fn check_kexec_disabled() -> bool {
    std::fs::read_to_string("/sys/module/kexec/parameters/enabled")
        .ok()
        .map(|s| s.trim() == "N")
        .unwrap_or(false)
}
