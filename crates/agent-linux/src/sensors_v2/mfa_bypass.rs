//! mfa_bypass sensor v2 - multi-factor auth bypass detection
//! Infer from auth chain patterns + config changes (PAM/sshd); emit mfa_bypass_suspect

use crate::core::Event;
use crate::linux::event_builders;
use crate::linux::host::HostCtx;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;

/// Collect mfa_bypass events
pub fn collect(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Check 1: High-precision invariant - PAM configuration anomalies
    events.extend(detect_pam_anomalies(host));

    // Check 2: Heuristic - SSH configuration weakening
    events.extend(detect_sshd_weakening(host));

    events
}

fn detect_pam_anomalies(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Check PAM configuration for MFA/2FA bypass patterns
    let pam_files = vec![
        "/etc/pam.d/sshd",
        "/etc/pam.d/sudo",
        "/etc/pam.d/login",
        "/etc/pam.d/system-auth",
    ];

    for pam_file in pam_files {
        if let Ok(content) = fs::read_to_string(pam_file) {
            // Check for pam_google_authenticator removal or disabling
            let disabled_mfa = content.contains("-pam_google_authenticator")
                || content.contains("-pam_duo")
                || content.contains("-pam_oath");

            if disabled_mfa {
                let key = format!("pam_disabled:{}", pam_file);
                if super::common::rate_limit("mfa_bypass", &key, 3600000) {
                    let mut fields = BTreeMap::new();
                    fields.insert("pam_file".to_string(), json!(pam_file));
                    fields.insert("mfa_module_disabled".to_string(), json!(true));

                    events.push(event_builders::event(
                        host,
                        "mfa_bypass",
                        "mfa_bypass_suspect",
                        "high",
                        fields,
                    ));
                }
            }

            // Check for reordering (auth sufficient before required) - weak pattern
            let lines: Vec<&str> = content.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                if line.contains("sufficient") && i > 0 {
                    if lines[i - 1].contains("required") && lines[i - 1].contains("pam_") {
                        let key = format!("pam_reorder:{}", pam_file);
                        if super::common::rate_limit("mfa_bypass", &key, 3600000) {
                            let mut fields = BTreeMap::new();
                            fields.insert("pam_file".to_string(), json!(pam_file));
                            fields.insert("control_reorder".to_string(), json!(true));

                            events.push(event_builders::event(
                                host,
                                "mfa_bypass",
                                "mfa_bypass_suspect",
                                "medium",
                                fields,
                            ));
                        }
                    }
                }
            }
        }
    }

    events
}

fn detect_sshd_weakening(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Check SSH daemon configuration
    if let Ok(content) = fs::read_to_string("/etc/ssh/sshd_config") {
        // Dangerous settings that weaken authentication
        let weak_settings = vec![
            ("PermitEmptyPasswords", "yes"),
            ("PasswordAuthentication", "yes"),
            ("ChallengeResponseAuthentication", "no"),
            ("PubkeyAuthentication", "no"),
            ("PermitRootLogin", "yes"),
        ];

        for (setting, dangerous_value) in weak_settings {
            for line in content.lines() {
                if line.starts_with('#') {
                    continue;
                }

                if line.contains(setting) && line.contains(dangerous_value) {
                    let key = format!("sshd:{}:{}", setting, dangerous_value);
                    if super::common::rate_limit("mfa_bypass", &key, 3600000) {
                        let mut fields = BTreeMap::new();
                        fields.insert("setting".to_string(), json!(setting));
                        fields.insert("value".to_string(), json!(dangerous_value));
                        fields.insert("weakens_auth".to_string(), json!(true));

                        events.push(event_builders::event(
                            host,
                            "mfa_bypass",
                            "mfa_bypass_suspect",
                            "high",
                            fields,
                        ));
                    }
                }
            }
        }
    }

    events
}
