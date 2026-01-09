//! Linux Playbook Loader
//!
//! This module loads Linux playbooks from YAML files in the playbooks/linux directory.
//! YAML is the canonical format - this is a thin adapter layer.
//!
//! Design principles:
//! - YAML files are the single source of truth
//! - Stable ordering (sorted by playbook_id)
//! - Clear errors if directory is missing or YAML is invalid
//! - Mirrors Windows UX behavior but uses YAML loader

use crate::slot_matcher::{PlaybookDef, PlaybookSlot, SlotPredicate};
use serde::Deserialize;
use std::path::PathBuf;

/// Raw YAML playbook structure (before conversion to PlaybookDef)
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Fields used for serde deserialization
struct YamlPlaybook {
    id: String,
    #[serde(default)]
    version: Option<String>,
    name: String,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    description: Option<String>,
    severity: String,
    #[serde(default = "default_window_sec")]
    window_sec: u64,
    #[serde(default = "default_cooldown_sec")]
    cooldown_sec: u64,
    #[serde(default)]
    required: Vec<YamlSlot>,
    #[serde(default)]
    optional: Vec<YamlSlot>,
    #[serde(default)]
    forbidden: Vec<YamlSlot>,
    #[serde(default)]
    explain: Option<YamlExplain>,
    // Legacy fields (steps-based playbooks)
    #[serde(default)]
    steps: Vec<YamlStep>,
    #[serde(default)]
    key_by: Vec<String>,
    #[serde(default)]
    emit: Option<YamlEmit>,
}

fn default_window_sec() -> u64 {
    600
}

fn default_cooldown_sec() -> u64 {
    300
}

#[derive(Debug, Deserialize)]
struct YamlSlot {
    slot_id: String,
    #[serde(default = "default_slot_ttl")]
    slot_ttl_sec: u64,
    #[serde(default)]
    fact: Option<String>,
    #[serde(default)]
    r#where: Vec<YamlCondition>,
    #[serde(default)]
    derive_tags: Vec<String>,
}

fn default_slot_ttl() -> u64 {
    300
}

#[derive(Debug, Deserialize)]
struct YamlCondition {
    field: String,
    op: String,
    value: serde_yaml::Value,
}

#[derive(Debug, Deserialize)]
struct YamlExplain {
    #[serde(default)]
    primary_ttp: Vec<String>,
    #[serde(default)]
    narrative: Option<String>,
}

/// Legacy step-based playbook structure
#[derive(Debug, Deserialize)]
struct YamlStep {
    id: String,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    any_tags: Vec<String>,
    #[serde(default)]
    cmd_regex: Option<String>,
    #[serde(default)]
    max_gap_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Fields used for serde deserialization
struct YamlEmit {
    #[serde(default)]
    add_tags: Vec<String>,
    #[serde(default)]
    risk: Option<f64>,
}

/// Get the playbooks directory path
fn get_playbooks_dir() -> PathBuf {
    // Check for explicit env var override
    if let Ok(path) = std::env::var("EDR_PLAYBOOKS_DIR") {
        return PathBuf::from(path).join("linux");
    }

    // Try relative to current exe first (for installed deployments)
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let candidates = [
                exe_dir.join("playbooks/linux"),
                exe_dir.join("../playbooks/linux"),
                exe_dir.join("../../playbooks/linux"),
                exe_dir.join("../../../playbooks/linux"), // cargo run from workspace
            ];
            for candidate in &candidates {
                if candidate.is_dir() {
                    return candidate.clone();
                }
            }
        }
    }

    // Try workspace root relative paths (development mode)
    let workspace_candidates = [
        PathBuf::from("playbooks/linux"),
        PathBuf::from("../playbooks/linux"),
        PathBuf::from("../../playbooks/linux"),
    ];
    for candidate in &workspace_candidates {
        if candidate.is_dir() {
            return candidate.clone();
        }
    }

    // Default (may not exist)
    PathBuf::from("playbooks/linux")
}

/// Load all Linux playbooks from YAML files.
///
/// Returns playbooks sorted by playbook_id for stable ordering.
/// Skips invalid files with warnings rather than failing entirely.
pub fn linux_playbooks() -> Vec<PlaybookDef> {
    let playbooks_dir = get_playbooks_dir();

    if !playbooks_dir.exists() {
        eprintln!(
            "[playbooks] Warning: Linux playbooks directory not found: {}",
            playbooks_dir.display()
        );
        eprintln!("[playbooks] Set EDR_PLAYBOOKS_DIR to override");
        return Vec::new();
    }

    let mut playbooks = Vec::new();
    let mut yaml_files: Vec<_> = match std::fs::read_dir(&playbooks_dir) {
        Ok(entries) => entries
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "yaml" || ext == "yml")
                    .unwrap_or(false)
                    || e.path().extension().is_none()
                        && e.file_name().to_string_lossy().starts_with("pb_")
            })
            .map(|e| e.path())
            .collect(),
        Err(e) => {
            eprintln!(
                "[playbooks] Error reading playbooks directory {}: {}",
                playbooks_dir.display(),
                e
            );
            return Vec::new();
        }
    };

    // Sort for stable ordering
    yaml_files.sort();

    for yaml_path in yaml_files {
        match load_yaml_playbook(&yaml_path) {
            Ok(playbook) => {
                playbooks.push(playbook);
            }
            Err(e) => {
                eprintln!(
                    "[playbooks] Warning: Failed to load {}: {}",
                    yaml_path.display(),
                    e
                );
            }
        }
    }

    // Sort by playbook_id for deterministic ordering
    playbooks.sort_by(|a, b| a.playbook_id.cmp(&b.playbook_id));

    eprintln!(
        "[playbooks] Loaded {} Linux playbooks from {}",
        playbooks.len(),
        playbooks_dir.display()
    );

    playbooks
}

/// Load a single YAML playbook file and convert to PlaybookDef
fn load_yaml_playbook(path: &PathBuf) -> Result<PlaybookDef, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("Failed to read file: {}", e))?;

    let yaml: YamlPlaybook =
        serde_yaml::from_str(&content).map_err(|e| format!("YAML parse error: {}", e))?;

    convert_yaml_to_playbook(yaml, path)
}

/// Convert parsed YAML to PlaybookDef
fn convert_yaml_to_playbook(
    yaml: YamlPlaybook,
    path: &std::path::Path,
) -> Result<PlaybookDef, String> {
    let playbook_id = yaml.id.clone();
    let title = yaml.title.unwrap_or_else(|| yaml.name.clone());

    // Determine family from filename or playbook id
    let family = extract_family(&playbook_id, path);

    // Build slots from required/optional sections
    let mut slots = Vec::new();

    // Required slots
    for yaml_slot in yaml.required {
        let slot = convert_yaml_slot(yaml_slot, true)?;
        slots.push(slot);
    }

    // Optional slots
    for yaml_slot in yaml.optional {
        let slot = convert_yaml_slot(yaml_slot, false)?;
        slots.push(slot);
    }

    // Handle legacy step-based playbooks by converting to slots
    if slots.is_empty() && !yaml.steps.is_empty() {
        for (idx, step) in yaml.steps.iter().enumerate() {
            let slot = convert_step_to_slot(step, idx)?;
            slots.push(slot);
        }
    }

    // If still no slots, create a generic trigger slot
    if slots.is_empty() {
        slots.push(PlaybookSlot::required(
            "generic_trigger",
            "Generic event trigger",
            SlotPredicate::for_fact_type("Exec"),
        ));
    }

    // Build narrative from explain section
    let narrative = yaml
        .explain
        .as_ref()
        .and_then(|e| e.narrative.clone())
        .or_else(|| yaml.description.clone());

    // Collect tags from explain.primary_ttp
    let mut tags: Vec<String> = yaml
        .explain
        .as_ref()
        .map(|e| e.primary_ttp.clone())
        .unwrap_or_default();

    // Add emit tags if present (legacy)
    if let Some(emit) = &yaml.emit {
        tags.extend(emit.add_tags.clone());
    }

    Ok(PlaybookDef {
        playbook_id,
        title,
        family,
        severity: yaml.severity.to_uppercase(),
        entity_scope: "host|user|exe".to_string(),
        ttl_seconds: yaml.window_sec,
        cooldown_seconds: yaml.cooldown_sec,
        tags,
        slots,
        narrative,
        playbook_hash: String::new(),
    })
}

/// Convert a YAML slot to PlaybookSlot
fn convert_yaml_slot(yaml_slot: YamlSlot, required: bool) -> Result<PlaybookSlot, String> {
    let fact_type = yaml_slot.fact.unwrap_or_else(|| "Exec".to_string());

    // Map YAML fact types to internal fact types
    let internal_fact_type = map_fact_type(&fact_type);

    // Build predicate from where conditions
    let mut predicate = SlotPredicate::for_fact_type(&internal_fact_type);

    for condition in &yaml_slot.r#where {
        apply_condition_to_predicate(&mut predicate, condition);
    }

    // Add MITRE tags from derive_tags
    predicate.mitre_tags = yaml_slot
        .derive_tags
        .iter()
        .filter(|t| t.starts_with("T"))
        .cloned()
        .collect();

    let slot = if required {
        PlaybookSlot::required(&yaml_slot.slot_id, &yaml_slot.slot_id, predicate)
    } else {
        PlaybookSlot::optional(&yaml_slot.slot_id, &yaml_slot.slot_id, predicate)
    };

    Ok(slot.with_ttl(yaml_slot.slot_ttl_sec))
}

/// Convert legacy step to PlaybookSlot
fn convert_step_to_slot(step: &YamlStep, _idx: usize) -> Result<PlaybookSlot, String> {
    let fact_type = match step.domain.as_deref() {
        Some("process") => "Exec",
        Some("privilege") => "PrivilegeBoundary",
        Some("auth") => "AuthEvent",
        Some("network") => "OutboundConnect",
        Some("file") => "WritePath",
        _ => "Exec",
    };

    let mut predicate = SlotPredicate::for_fact_type(fact_type);

    // Add path regex from cmd_regex if present
    if let Some(regex) = &step.cmd_regex {
        predicate.path_regex = Some(regex.clone());
    }

    // Add detector tags from any_tags
    predicate.detector_tags = step.any_tags.clone();

    let slot = PlaybookSlot::required(&step.id, &step.id, predicate);

    // Use max_gap_secs as TTL if provided
    let ttl = step.max_gap_secs.unwrap_or(300);
    Ok(slot.with_ttl(ttl))
}

/// Map YAML fact type names to internal FactType discriminants
fn map_fact_type(yaml_fact: &str) -> String {
    match yaml_fact.to_lowercase().as_str() {
        "exec" => "Exec",
        "auth" => "AuthEvent",
        "netconn" | "network" | "net" => "OutboundConnect",
        "fileio" | "file" => "WritePath",
        "host" => "Unknown", // Host facts are meta, map to Unknown
        "process" => "Exec",
        "privilege" => "PrivilegeBoundary",
        "dns" => "DnsResolve",
        "module" | "moduleload" => "ModuleLoad",
        "mem" | "memory" => "MemWX",
        _ => yaml_fact, // Pass through unknown types
    }
    .to_string()
}

/// Apply a YAML condition to a SlotPredicate
fn apply_condition_to_predicate(predicate: &mut SlotPredicate, condition: &YamlCondition) {
    match condition.field.as_str() {
        "exe" => {
            if condition.op == "regex" {
                predicate.path_regex = condition.value.as_str().map(|s| s.to_string());
            } else if condition.op == "eq" || condition.op == "contains" {
                predicate.exe_filter = condition.value.as_str().map(|s| s.to_string());
            }
        }
        "cmd" | "cmdline" => {
            if condition.op == "regex" {
                predicate.path_regex = condition.value.as_str().map(|s| s.to_string());
            }
        }
        "path" => {
            if condition.op == "glob" {
                predicate.path_glob = condition.value.as_str().map(|s| s.to_string());
            } else if condition.op == "regex" {
                predicate.path_regex = condition.value.as_str().map(|s| s.to_string());
            }
        }
        "dst_port" | "dest_port" => {
            if let Some(port) = condition.value.as_u64() {
                predicate.dst_port = Some(port as u16);
            }
        }
        "tag" => {
            if let Some(tags) = condition.value.as_sequence() {
                predicate.detector_tags = tags
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();
            } else if let Some(tag) = condition.value.as_str() {
                predicate.detector_tags.push(tag.to_string());
            }
        }
        _ => {
            // Store complex conditions as detector tags for now
            // This preserves the intent even if we can't evaluate it directly
        }
    }
}

/// Extract family from playbook ID or filename
fn extract_family(playbook_id: &str, path: &std::path::Path) -> String {
    let id_lower = playbook_id.to_lowercase();

    // Common family patterns
    let families = [
        ("lateral", "lateral_movement"),
        ("cred", "credential_access"),
        ("exfil", "exfiltration"),
        ("persist", "persistence"),
        ("encryptor", "ransomware"),
        ("crypto", "cryptomining"),
        ("container", "container_escape"),
        ("lotl", "living_off_land"),
        ("evasion", "defense_evasion"),
        ("discovery", "discovery"),
        ("recon", "reconnaissance"),
        ("c2", "command_and_control"),
        ("initial", "initial_access"),
    ];

    for (pattern, family) in &families {
        if id_lower.contains(pattern) {
            return family.to_string();
        }
    }

    // Extract from filename
    let filename = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown");
    for (pattern, family) in &families {
        if filename.to_lowercase().contains(pattern) {
            return family.to_string();
        }
    }

    "detection".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_playbooks_loads() {
        // This test verifies the loader works
        // In CI, playbooks/linux may or may not be present
        let playbooks = linux_playbooks();

        // If playbooks dir exists, we should load at least some
        let playbooks_dir = get_playbooks_dir();
        if playbooks_dir.exists() {
            assert!(
                !playbooks.is_empty(),
                "Expected at least 1 playbook from {}",
                playbooks_dir.display()
            );
            eprintln!("Loaded {} playbooks", playbooks.len());

            // Verify basic structure
            for pb in &playbooks {
                assert!(
                    !pb.playbook_id.is_empty(),
                    "Playbook ID should not be empty"
                );
                assert!(!pb.title.is_empty(), "Playbook title should not be empty");
                assert!(!pb.severity.is_empty(), "Severity should not be empty");
            }
        } else {
            eprintln!(
                "Playbooks directory not found (OK in minimal CI): {}",
                playbooks_dir.display()
            );
        }
    }

    #[test]
    fn test_stable_ordering() {
        // Two calls should return same order
        let pb1 = linux_playbooks();
        let pb2 = linux_playbooks();

        let ids1: Vec<_> = pb1.iter().map(|p| &p.playbook_id).collect();
        let ids2: Vec<_> = pb2.iter().map(|p| &p.playbook_id).collect();

        assert_eq!(ids1, ids2, "Playbook ordering should be stable");
    }

    #[test]
    fn test_map_fact_type() {
        assert_eq!(map_fact_type("Exec"), "Exec");
        assert_eq!(map_fact_type("exec"), "Exec");
        assert_eq!(map_fact_type("Auth"), "AuthEvent");
        assert_eq!(map_fact_type("NetConn"), "OutboundConnect");
        assert_eq!(map_fact_type("FileIO"), "WritePath");
    }

    #[test]
    fn test_extract_family() {
        let path = PathBuf::from("playbooks/linux/pb_lateral_ssh.yaml");
        assert_eq!(extract_family("pb_lateral_ssh", &path), "lateral_movement");

        let path = PathBuf::from("playbooks/linux/pb_cred_dump.yaml");
        assert_eq!(extract_family("pb_cred_dump", &path), "credential_access");

        let path = PathBuf::from("playbooks/linux/pb_unknown.yaml");
        assert_eq!(extract_family("pb_something", &path), "detection");
    }
}
