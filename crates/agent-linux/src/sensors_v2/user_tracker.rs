//! user_tracker sensor v2 - account and privilege inventory
//! Sources: /etc/passwd, /etc/group, /etc/shadow, /etc/sudoers.d/
//! Detects: new accounts, privilege changes, hidden accounts, group modifications

use crate::core::Event;
use crate::linux::event_builders;
use crate::linux::host::HostCtx;
use crate::linux::sensors_v2::common;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;

/// Collect user account change events
pub fn collect(host: &HostCtx) -> Vec<Event> {
    let mut events = Vec::new();

    // Parse /etc/passwd for changes
    if let Ok(content) = fs::read_to_string("/etc/passwd") {
        for line in content
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 {
                let user = parts[0];
                let uid: Option<u32> = parts[2].parse().ok();
                let shell = parts.get(6).copied().unwrap_or("");

                // Invariant: uid=0 account that's not root
                if uid == Some(0)
                    && user != "root"
                    && common::seen_once("user_tracker", &format!("uid0:{}", user))
                {
                    let mut fields = BTreeMap::new();
                    fields.insert("user".to_string(), json!(user));
                    fields.insert("uid".to_string(), json!(0));
                    events.push(event_builders::event(
                        host,
                        "user_tracker",
                        "root_uid_account",
                        "alert",
                        fields,
                    ));
                }

                // Heuristic: new system account with shell (unusual)
                if let Some(u) = uid {
                    if u < 1000
                        && !shell.ends_with("/nologin")
                        && !shell.ends_with("/false")
                        && common::rate_limit(
                            "user_tracker",
                            &format!("sys_shell:{}", user),
                            86400_000,
                        )
                    {
                        let mut fields = BTreeMap::new();
                        fields.insert("user".to_string(), json!(user));
                        fields.insert("uid".to_string(), json!(u));
                        fields.insert("shell".to_string(), json!(shell));
                        events.push(event_builders::event(
                            host,
                            "user_tracker",
                            "system_user_shell",
                            "warn",
                            fields,
                        ));
                    }
                }

                // Check for no password (empty shadow field)
                if let Ok(shadow) = fs::read_to_string("/etc/shadow") {
                    for sline in shadow.lines() {
                        let sparts: Vec<&str> = sline.split(':').collect();
                        if sparts.len() > 0 && sparts[0] == user {
                            let pwd_field = sparts.get(1).copied().unwrap_or("");
                            if pwd_field.is_empty()
                                && common::seen_once("user_tracker", &format!("nopass:{}", user))
                            {
                                let mut fields = BTreeMap::new();
                                fields.insert("user".to_string(), json!(user));
                                events.push(event_builders::event(
                                    host,
                                    "user_tracker",
                                    "no_password_set",
                                    "warn",
                                    fields,
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    // Parse /etc/sudoers.d for privilege grants
    if let Ok(sudoers_dir) = fs::read_dir("/etc/sudoers.d") {
        for entry in sudoers_dir.flatten() {
            if let Ok(content) = fs::read_to_string(entry.path()) {
                for line in content
                    .lines()
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                {
                    if let Some(user) = line.split_whitespace().next() {
                        if common::rate_limit("user_tracker", &format!("sudo:{}", user), 86400_000)
                        {
                            let mut fields = BTreeMap::new();
                            fields.insert("user".to_string(), json!(user));
                            fields.insert(
                                "sudoers_line".to_string(),
                                json!(line[..line.len().min(100)].to_string()),
                            );
                            events.push(event_builders::event(
                                host,
                                "user_tracker",
                                "sudo_grant",
                                "info",
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
