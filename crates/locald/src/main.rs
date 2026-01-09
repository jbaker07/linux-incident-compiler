//! EDR Locald entry point - Platform-adaptive signal detection daemon
//!
//! Pipeline: segments/*.jsonl -> extract_facts -> HypothesisController -> Incidents -> signals table -> edr-server
//!
//! This is the FULL detection pipeline that uses:
//! - PlaybookDef: Playbook definitions with slot predicates (loaded from YAML on Linux)
//! - extract_facts: Convert platform events to canonical Facts
//! - HypothesisController: Slot matching, TTL, cooldowns, incident promotion
//! - Signal persistence: Store fired incidents as signals for API
//! - ExplanationBundle: Full explainability for each signal

use chrono::Utc;
use edr_core::{Event, EvidencePtr};
#[cfg(target_os = "windows")]
use edr_locald::explanation_builder::build_explanation_from_hypothesis;
use edr_locald::hypothesis_controller::HypothesisController;
use edr_locald::load_metrics::{db_metrics, locald_metrics};
use edr_locald::scoring::ScoringEngine;
use edr_locald::signal_result::SignalResult;
use edr_locald::slot_matcher::PlaybookDef;

// Platform-specific imports - Fact types differ between platforms
#[cfg(target_os = "linux")]
use edr_locald::canonical::fact::Fact as CanonicalFact;
#[cfg(target_os = "linux")]
use edr_locald::os::linux::{extract_facts, linux_playbooks, LinuxSignalEngine};

#[cfg(target_os = "windows")]
use edr_locald::hypothesis::Fact;
#[cfg(target_os = "windows")]
use edr_locald::os::windows::{extract_facts, windows_playbooks, WindowsSignalEngine};
use rusqlite::{params, Connection};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Get telemetry root from env or default
fn get_telemetry_root() -> PathBuf {
    std::env::var("EDR_TELEMETRY_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            if cfg!(windows) {
                PathBuf::from(r"C:\ProgramData\edr")
            } else {
                PathBuf::from("/var/lib/edr")
            }
        })
}

/// Index file structure
#[derive(Debug, Deserialize)]
struct SegmentIndex {
    #[allow(dead_code)]
    schema_version: u32,
    segments: Vec<SegmentEntry>,
}

#[derive(Debug, Deserialize)]
struct SegmentEntry {
    #[serde(alias = "path", alias = "rel_path")]
    path: Option<String>,
    #[allow(dead_code)]
    stream_id: Option<String>,
}

impl SegmentEntry {
    fn get_path(&self) -> Option<&str> {
        self.path.as_deref()
    }
}

/// Parse a segment JSONL record into edr_core::Event
fn parse_segment_record(line: &str, segment_id: u64, record_index: u32) -> Option<Event> {
    let parsed: serde_json::Value = serde_json::from_str(line).ok()?;

    let ts_ms = parsed.get("ts_ms")?.as_i64()?;
    let host = parsed.get("host")?.as_str()?.to_string();

    let tags: Vec<String> = parsed
        .get("tags")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default();

    // Extract fields from the "fields" object
    let fields: BTreeMap<String, serde_json::Value> = parsed
        .get("fields")
        .and_then(|v| v.as_object())
        .map(|obj| obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default();

    // Build evidence pointer from segment record
    let evidence_ptr = parsed.get("evidence_ptr").and_then(|ep| {
        let stream_id = ep.get("stream_id")?.as_str()?.to_string();
        Some(EvidencePtr {
            stream_id,
            segment_id,
            record_index,
        })
    });

    Some(Event {
        ts_ms,
        host,
        tags,
        proc_key: parsed
            .get("proc_key")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        file_key: parsed
            .get("file_key")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        identity_key: parsed
            .get("identity_key")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        evidence_ptr,
        fields,
    })
}

/// Convert an incident to a SignalResult for database persistence
#[cfg(target_os = "windows")]
fn incident_to_signal(incident: &edr_locald::hypothesis::Incident, hostname: &str) -> SignalResult {
    use edr_locald::signal_result::EvidenceRef;

    let evidence_refs: Vec<EvidenceRef> = incident
        .evidence_ptrs_summary
        .iter()
        .map(|ep| EvidenceRef {
            stream_id: ep.stream_id.clone(),
            segment_id: ep.segment_id.clone(),
            record_index: ep.record_index,
        })
        .collect();

    // Build metadata JSON
    let metadata = serde_json::json!({
        "family": incident.family,
        "primary_scope_key": format!("{:?}", incident.primary_scope_key),
        "confidence": incident.confidence,
        "mitre_techniques": incident.mitre_techniques,
        "tags": incident.tags.iter().collect::<Vec<_>>(),
        "promoted_from": incident.promoted_from_hypothesis_ids,
    });

    SignalResult {
        signal_id: incident.incident_id.clone(),
        signal_type: format!("playbook:{}", incident.family),
        severity: format!("{:?}", incident.severity),
        host: hostname.to_string(),
        ts: incident.first_ts.timestamp_millis(),
        ts_start: incident.first_ts.timestamp_millis(),
        ts_end: incident.last_ts.timestamp_millis(),
        proc_key: None,
        file_key: None,
        identity_key: None,
        evidence_ptrs: evidence_refs,
        dropped_evidence_count: 0,
        metadata,
    }
}

fn main() {
    let telemetry_root = get_telemetry_root();

    eprintln!("edr-locald starting (FULL PIPELINE MODE)");
    eprintln!("TELEMETRY_ROOT: {}", telemetry_root.display());

    // Check workflow seed env var (for backward compatibility)
    let workflow_seed = std::env::var("EDR_WORKFLOW_SEED")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false);
    if workflow_seed {
        eprintln!("EDR_WORKFLOW_SEED: enabled (will also emit synthetic WorkflowSeed signal)");
    }

    // Ensure directories exist
    let segments_dir = telemetry_root.join("segments");
    if let Err(e) = fs::create_dir_all(&segments_dir) {
        eprintln!("ERROR: Failed to create segments dir: {}", e);
        return;
    }

    // Initialize SQLite database (use same db as edr-server for API compatibility)
    let db_path = telemetry_root.join("workbench.db");
    let db = match Connection::open(&db_path) {
        Ok(conn) => {
            // Create signals table (same schema as edr-server for /api/signals)
            let _ = conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS signals (
                    signal_id TEXT PRIMARY KEY,
                    signal_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    host TEXT NOT NULL,
                    ts INTEGER NOT NULL,
                    ts_start INTEGER NOT NULL,
                    ts_end INTEGER NOT NULL,
                    proc_key TEXT,
                    file_key TEXT,
                    identity_key TEXT,
                    metadata TEXT NOT NULL,
                    evidence_ptrs TEXT NOT NULL,
                    dropped_evidence_count INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_signals_ts ON signals(ts DESC);
                CREATE INDEX IF NOT EXISTS idx_signals_type ON signals(signal_type);
                CREATE INDEX IF NOT EXISTS idx_signals_host ON signals(host);
                CREATE INDEX IF NOT EXISTS idx_signals_severity ON signals(severity);

                CREATE TABLE IF NOT EXISTS signal_explanations (
                    signal_id TEXT PRIMARY KEY,
                    explanation_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (signal_id) REFERENCES signals(signal_id)
                );
                CREATE INDEX IF NOT EXISTS idx_explanations_signal ON signal_explanations(signal_id);

                CREATE TABLE IF NOT EXISTS locald_checkpoint (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );",
            );
            eprintln!("Database: {}", db_path.display());
            conn
        }
        Err(e) => {
            eprintln!("FATAL: Failed to open database: {}", e);
            return;
        }
    };

    // Initialize hostname
    let hostname = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown".to_string());
    eprintln!("Host: {}", hostname);

    // Initialize HypothesisController (the core of playbook-based detection)
    let mut hypothesis_controller = HypothesisController::new(&hostname);

    // Load platform-specific playbooks into the controller (and keep a map for explanations)
    #[cfg(target_os = "linux")]
    let playbooks = linux_playbooks();
    #[cfg(target_os = "windows")]
    let playbooks = windows_playbooks();
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    let playbooks: Vec<PlaybookDef> = Vec::new();

    let playbook_count = playbooks.len();
    let mut playbook_map: HashMap<String, PlaybookDef> = HashMap::new();
    for playbook in playbooks {
        eprintln!(
            "  [playbook] Registered: {} (family={}, slots={})",
            playbook.playbook_id,
            playbook.family,
            playbook.slots.len()
        );
        playbook_map.insert(playbook.playbook_id.clone(), playbook.clone());
        hypothesis_controller.register_playbook(playbook);
    }
    #[cfg(target_os = "linux")]
    eprintln!("Loaded {} Linux playbooks from YAML", playbook_count);
    #[cfg(target_os = "windows")]
    eprintln!("Loaded {} Windows playbooks", playbook_count);
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    eprintln!(
        "Warning: No playbooks loaded for this platform ({})",
        std::env::consts::OS
    );

    // Track facts for explanation building (platform-specific types)
    // Note: On Linux, canonical::fact::Fact is used; on Windows, hypothesis::Fact
    #[cfg(target_os = "linux")]
    let mut facts_store: Vec<CanonicalFact> = Vec::new();
    #[cfg(target_os = "windows")]
    let mut facts_store: Vec<Fact> = Vec::new();

    // Initialize platform-specific signal engine (for WorkflowSeed only if enabled)
    #[cfg(target_os = "linux")]
    let mut signal_engine = LinuxSignalEngine::new(hostname.clone());
    #[cfg(target_os = "windows")]
    let mut signal_engine = WindowsSignalEngine::new(hostname.clone());

    // Initialize scoring engine
    let scoring_engine = ScoringEngine::new(false);

    // Track processed segments
    let mut seen_segments: HashSet<String> = HashSet::new();

    // Load checkpoint
    if let Ok(checkpoint) = db.query_row::<String, _, _>(
        "SELECT value FROM locald_checkpoint WHERE key = 'seen_segments'",
        [],
        |row| row.get(0),
    ) {
        for seg in checkpoint.split(',') {
            if !seg.is_empty() {
                seen_segments.insert(seg.to_string());
            }
        }
        eprintln!(
            "Resumed from checkpoint with {} segments",
            seen_segments.len()
        );
    }

    // Setup graceful shutdown
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        eprintln!("\n[locald] Shutting down...");
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .ok();

    let index_path = telemetry_root.join("index.json");
    eprintln!("Watching: {}", index_path.display());
    eprintln!("(Press Ctrl+C to stop)");

    let mut total_events = 0u64;
    let mut total_facts = 0u64;
    let mut total_signals = 0u64;
    #[cfg(target_os = "windows")]
    let mut incidents_fired: HashSet<String> = HashSet::new();

    // Main loop
    while !shutdown.load(Ordering::Relaxed) {
        // Read index.json
        if let Ok(index_content) = fs::read_to_string(&index_path) {
            if let Ok(index) = serde_json::from_str::<SegmentIndex>(&index_content) {
                for entry in &index.segments {
                    let entry_path = match entry.get_path() {
                        Some(p) => p.to_string(),
                        None => continue,
                    };

                    if seen_segments.contains(&entry_path) {
                        continue;
                    }

                    let segment_path = telemetry_root.join(&entry_path);
                    if !segment_path.exists() {
                        continue;
                    }

                    // Extract segment_id from filename (e.g., "segments/1234.jsonl" -> 1234)
                    let segment_id: u64 = segment_path
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);

                    eprintln!("[ingest] Processing: {}", entry_path);

                    // Track segment processing for load metrics
                    locald_metrics().record_segment_seen();

                    if let Ok(content) = fs::read_to_string(&segment_path) {
                        let mut segment_events = 0u32;
                        let mut segment_facts = 0u32;
                        let mut segment_signals = 0u32;

                        for (record_index, line) in content.lines().enumerate() {
                            if line.trim().is_empty() {
                                continue;
                            }

                            if let Some(event) =
                                parse_segment_record(line, segment_id, record_index as u32)
                            {
                                segment_events += 1;

                                // === FULL PIPELINE: Extract Facts ===
                                let fact_start = Instant::now();
                                let facts = extract_facts(&event);
                                locald_metrics()
                                    .record_fact_extract(fact_start.elapsed().as_millis() as u64);
                                segment_facts += facts.len() as u32;

                                // === FULL PIPELINE: Feed Facts to HypothesisController ===
                                // Note: On Linux, canonical::Fact differs from hypothesis::Fact
                                // Until unified, Linux uses signal engine directly; Windows uses HypothesisController
                                #[cfg(target_os = "windows")]
                                for fact in facts {
                                    // Store fact for explanation building
                                    facts_store.push(fact.clone());

                                    let playbook_start = Instant::now();
                                    match hypothesis_controller.ingest_fact(fact) {
                                        Ok(affected_hypotheses) => {
                                            locald_metrics().record_playbook_eval(
                                                playbook_start.elapsed().as_millis() as u64,
                                            );
                                            if !affected_hypotheses.is_empty() {
                                                eprintln!(
                                                    "    [fact] Affected {} hypotheses",
                                                    affected_hypotheses.len()
                                                );
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!("    [fact] Error: {}", e);
                                        }
                                    }
                                }

                                #[cfg(target_os = "linux")]
                                {
                                    // Store facts for potential future use
                                    for fact in facts {
                                        facts_store.push(fact);
                                    }
                                    // TODO: Convert canonical::Fact to hypothesis::Fact for HypothesisController
                                    // For now, Linux uses signal engine directly
                                }

                                // === SIGNAL ENGINE: Process events directly ===
                                // This works on both platforms and generates signals
                                let engine_signals = signal_engine.process_event(&event);
                                for signal in engine_signals {
                                    segment_signals += 1;
                                    let scored = scoring_engine.score(signal.clone());
                                    persist_signal(&db, &signal, &scored.risk_score);
                                    eprintln!(
                                        "  [signal] {} severity={} risk={:.2}",
                                        scored.signal.signal_type,
                                        scored.signal.severity,
                                        scored.risk_score
                                    );
                                }
                            }
                        }

                        // === FULL PIPELINE: Check for fired incidents ===
                        // HypothesisController promotes hypotheses to incidents automatically
                        hypothesis_controller.expire_hypotheses();

                        // Persist any new incidents as signals with explanations
                        // Note: On Linux, incidents are not yet generated via HypothesisController
                        // because canonical::Fact differs from hypothesis::Fact.
                        // Signal engine handles signal generation directly.
                        #[cfg(target_os = "windows")]
                        {
                            let all_incidents = hypothesis_controller.all_incidents();
                            for incident in all_incidents {
                                if !incidents_fired.contains(&incident.incident_id) {
                                    // Convert incident to signal and persist
                                    let signal = incident_to_signal(incident, &hostname);
                                    segment_signals += 1;

                                    let evidence_json =
                                        serde_json::to_string(&signal.evidence_ptrs)
                                            .unwrap_or_else(|_| "[]".to_string());
                                    let metadata_json = signal.metadata.to_string();
                                    let created_at = Utc::now().to_rfc3339();

                                    let _ = db.execute(
                                    "INSERT OR REPLACE INTO signals
                                     (signal_id, signal_type, severity, host, ts, ts_start, ts_end, proc_key, file_key, identity_key, metadata, evidence_ptrs, dropped_evidence_count, created_at)
                                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                                    params![
                                        signal.signal_id,
                                        signal.signal_type,
                                        signal.severity,
                                        signal.host,
                                        signal.ts,
                                        signal.ts_start,
                                        signal.ts_end,
                                        signal.proc_key,
                                        signal.file_key,
                                        signal.identity_key,
                                        metadata_json,
                                        evidence_json,
                                        signal.dropped_evidence_count,
                                        &created_at
                                    ],
                                );

                                    // === BUILD AND PERSIST EXPLANATION BUNDLE ===
                                    // Find hypothesis that promoted to this incident
                                    if let Some(hyp_id) =
                                        incident.promoted_from_hypothesis_ids.first()
                                    {
                                        if let Some(hypothesis) =
                                            hypothesis_controller.get_hypothesis(hyp_id)
                                        {
                                            // Find playbook for this hypothesis
                                            if let Some(playbook) =
                                                playbook_map.get(&hypothesis.template_id)
                                            {
                                                let explanation = build_explanation_from_hypothesis(
                                                    hypothesis,
                                                    incident,
                                                    playbook,
                                                    &telemetry_root,
                                                    &facts_store,
                                                );

                                                // Persist explanation
                                                if let Ok(explanation_json) =
                                                    serde_json::to_string(&explanation)
                                                {
                                                    let _ = db.execute(
                                                        "INSERT OR REPLACE INTO signal_explanations
                                                     (signal_id, explanation_json, created_at)
                                                     VALUES (?1, ?2, ?3)",
                                                        params![
                                                            signal.signal_id,
                                                            explanation_json,
                                                            &created_at
                                                        ],
                                                    );
                                                    eprintln!(
                                                    "  [explanation] {} → {} slots, {} evidence",
                                                    signal.signal_id,
                                                    explanation.slots.len(),
                                                    explanation.evidence.len()
                                                );
                                                }
                                            }
                                        }
                                    }

                                    eprintln!(
                                        "  [persisted] {} → {} severity={:?}",
                                        signal.signal_id, signal.signal_type, incident.severity
                                    );

                                    incidents_fired.insert(incident.incident_id.clone());
                                }
                            }
                        } // end #[cfg(target_os = "windows")]

                        // Check active hypotheses for debugging
                        let active = hypothesis_controller.active_hypotheses();
                        if !active.is_empty() {
                            eprintln!("  [hypothesis] {} active hypotheses", active.len());
                        }

                        total_events += segment_events as u64;
                        total_facts += segment_facts as u64;
                        total_signals += segment_signals as u64;

                        // Update load metrics for segment completion
                        locald_metrics().record_segment_processed();
                        locald_metrics().record_records_processed(segment_events as u64);

                        // Update last processed timestamp for lag calculation
                        locald_metrics()
                            .set_last_processed_ts(chrono::Utc::now().timestamp_millis());

                        eprintln!(
                            "  [done] {} events, {} facts, {} signals (total: {} events, {} facts, {} signals)",
                            segment_events, segment_facts, segment_signals, total_events, total_facts, total_signals
                        );
                    }

                    seen_segments.insert(entry_path.clone());

                    // Save checkpoint with timing
                    let checkpoint = seen_segments.iter().cloned().collect::<Vec<_>>().join(",");
                    let commit_start = Instant::now();
                    let _ = db.execute(
                        "INSERT OR REPLACE INTO locald_checkpoint (key, value) VALUES ('seen_segments', ?1)",
                        params![checkpoint],
                    );
                    db_metrics().record_txn_commit(commit_start.elapsed().as_millis() as u64);
                }
            }
        }

        // Poll every 2 seconds
        std::thread::sleep(Duration::from_secs(2));
    }

    eprintln!(
        "edr-locald stopped. Total: {} events, {} facts, {} signals",
        total_events, total_facts, total_signals
    );
}

/// Persist a signal to the database
fn persist_signal(db: &Connection, signal: &SignalResult, _risk_score: &f64) {
    let evidence_json =
        serde_json::to_string(&signal.evidence_ptrs).unwrap_or_else(|_| "[]".to_string());
    let metadata_json = signal.metadata.to_string();
    let created_at = Utc::now().to_rfc3339();

    let _ = db.execute(
        "INSERT OR REPLACE INTO signals
         (signal_id, signal_type, severity, host, ts, ts_start, ts_end, proc_key, file_key, identity_key, metadata, evidence_ptrs, dropped_evidence_count, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            signal.signal_id,
            signal.signal_type,
            signal.severity,
            signal.host,
            signal.ts,
            signal.ts_start,
            signal.ts_end,
            signal.proc_key,
            signal.file_key,
            Option::<String>::None, // identity_key
            metadata_json,
            evidence_json,
            signal.dropped_evidence_count,
            created_at
        ],
    );
}
