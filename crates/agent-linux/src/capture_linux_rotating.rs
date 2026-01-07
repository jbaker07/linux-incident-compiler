//! Linux event capture with rotating segments (v2)
//! Collects from both eBPF (ringbuf/perf) and sensors_v2
//! Writes deterministically-sorted events to append-only JSONL segments
//! EvidencePtr authority: assigns stream_id, segment_id, record_index at write time

use anyhow::Result;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

use crate::core::Event;
use crate::linux::host::HostCtx;
use crate::linux::sensors_v2;

const SEGMENT_SIZE_BYTES: usize = 100 * 1024 * 1024;
const STREAM_ID: &str = "linux_capture_0";

pub struct LinuxCapture {
    base_dir: PathBuf,
    segment_id: u64,
    record_index: u32,
    current_segment: Option<SegmentWriter>,
    host: HostCtx,
    #[cfg(target_os = "linux")]
    ebpf_reader: Option<crate::linux::ebpf::EbpfReader>,
    #[cfg(target_os = "linux")]
    ebpf_metrics: crate::linux::ebpf::MetricsCollector,
    // Attack surface event counters
    priv_uid_change_count: u64,
    priv_gid_change_count: u64,
    priv_cap_change_count: u64,
    priv_boundary_cross_count: u64,
    net_connect_count: u64,
    remote_tool_exec_count: u64,
    log_tamper_count: u64,
    audit_tamper_count: u64,
    c2_suspected_count: u64,
    // Parity primitives (Linux) - Original 4 types
    cred_access_count: u64,
    discovery_exec_count: u64,
    archive_tool_exec_count: u64,
    staging_write_count: u64,
    net_connect_prim_count: u64,
    // Extended 5 canonical primitives (Linux parity)
    persistence_change_count: u64,
    defense_evasion_count: u64,
    process_injection_count: u64,
    auth_event_count: u64,
    script_exec_count: u64,
}

struct SegmentWriter {
    file: File,
    path: PathBuf,
    bytes_written: usize,
}

impl LinuxCapture {
    pub fn new(base_dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&base_dir)?;
        let host = HostCtx::new();

        #[cfg(target_os = "linux")]
        {
            let ebpf_config = crate::linux::ebpf::EbpfConfig::from_env();
            let _ = ebpf_config.setup_memlock();

            // Write capture PID to protected_pids map if available
            let capture_pid = std::process::id();
            if let Err(e) = crate::linux::ebpf::write_protected_pid(capture_pid) {
                eprintln!(
                    "[LinuxCapture::new] Could not write protected PID {}: {}",
                    capture_pid, e
                );
                // Non-fatal: continue
            }
        }

        #[cfg(target_os = "linux")]
        let ebpf_reader = {
            let config = crate::linux::ebpf::ReaderConfig::default();
            let (reader, _thread) = crate::linux::ebpf::EbpfReader::new(config);
            // Thread runs in background; reader lives here
            Some(reader)
        };

        #[cfg(target_os = "linux")]
        let mut ebpf_metrics = crate::linux::ebpf::MetricsCollector::new();
        #[cfg(target_os = "linux")]
        ebpf_metrics.set_transport("ebpf+pinned");

        Ok(Self {
            base_dir,
            segment_id: 0,
            record_index: 0,
            current_segment: None,
            host,
            #[cfg(target_os = "linux")]
            ebpf_reader,
            #[cfg(target_os = "linux")]
            ebpf_metrics,
            priv_uid_change_count: 0,
            priv_gid_change_count: 0,
            priv_cap_change_count: 0,
            priv_boundary_cross_count: 0,
            net_connect_count: 0,
            remote_tool_exec_count: 0,
            log_tamper_count: 0,
            audit_tamper_count: 0,
            c2_suspected_count: 0,
            cred_access_count: 0,
            discovery_exec_count: 0,
            archive_tool_exec_count: 0,
            staging_write_count: 0,
            net_connect_prim_count: 0,
            persistence_change_count: 0,
            defense_evasion_count: 0,
            process_injection_count: 0,
            auth_event_count: 0,
            script_exec_count: 0,
        })
    }

    /// Run one iteration of capture: unified eBPF + sensors_v2 collection
    pub fn poll_and_write(&mut self) -> Result<()> {
        let mut events = Vec::new();

        // Collect from sensors_v2 (synchronous, bounded)
        let mut sensor_events = sensors_v2::collect_all(&self.host);
        let sensors_count = sensor_events.len();

        // Enforce: sensors_v2 must emit None for evidence_ptr
        for evt in &mut sensor_events {
            evt.evidence_ptr = None;
        }
        events.extend(sensor_events);

        // Collect from eBPF ringbuf/perf maps (non-blocking poll)
        #[cfg(target_os = "linux")]
        {
            if let Some(reader) = &mut self.ebpf_reader {
                let mut ebpf_count = 0;
                let mut decode_errors = 0;

                // Non-blocking drain of queued events
                while let Some(raw_event) = reader.try_recv() {
                    match crate::linux::ebpf::decode_ebpf_event(&raw_event) {
                        Ok(mut evt) => {
                            // Ensure no EvidencePtr before capture assigns it
                            evt.evidence_ptr = None;
                            events.push(evt);
                            ebpf_count += 1;
                        }
                        Err(_) => {
                            decode_errors += 1;
                        }
                    }
                }

                self.ebpf_metrics.record_events_read(ebpf_count as u64);
                self.ebpf_metrics.record_decode_failed(decode_errors as u64);
            }
        }

        // Deterministically sort all events by (timestamp, event_type, pid, uid)
        sort_events(&mut events);

        // Derive parity primitives from base events (exec, file, network)
        let mut derived_events = Vec::new();
        for event in &events {
            let primitives = crate::linux::sensors::ebpf_primitives::derive_primitive_events(event);
            derived_events.extend(primitives);
        }

        // Merge derived events back into main events list
        events.extend(derived_events);

        // Re-sort after adding derived primitives
        sort_events(&mut events);

        // Dedup derived primitives: maintain a set of (ts_ms, event_type, critical_fields)
        // This prevents duplicate primitives from base events that appear twice in same poll
        // Now covers all 9 canonical primitive types
        let mut seen_derived = HashSet::new();
        let mut deduped_events = Vec::new();

        for event in events {
            // Check if this is a derived primitive by tags (all 9 canonical types)
            let is_derived = event.tags.contains(&"credential_access".to_string())
                || event.tags.contains(&"discovery".to_string())
                || event.tags.contains(&"exfiltration".to_string())
                || event.tags.contains(&"network_connection".to_string())
                || event.tags.contains(&"persistence_change".to_string())
                || event.tags.contains(&"defense_evasion".to_string())
                || event.tags.contains(&"process_injection".to_string())
                || event.tags.contains(&"auth_event".to_string())
                || event.tags.contains(&"script_exec".to_string());

            if is_derived {
                // Generate minimal dedup key for derived primitives
                let dedup_key = generate_dedup_key(&event);

                if seen_derived.contains(&dedup_key) {
                    // Skip duplicate derived primitive from this poll window
                    continue;
                }
                seen_derived.insert(dedup_key);
            }

            deduped_events.push(event);
        }

        let events = deduped_events;

        // Count attack surface events before writing
        for event in &events {
            // Check for existing attack surface events
            match event
                .fields
                .get(crate::core::event_keys::EVENT_KIND)
                .and_then(|v| v.as_str())
            {
                Some("priv_uid_change") => self.priv_uid_change_count += 1,
                Some("priv_gid_change") => self.priv_gid_change_count += 1,
                Some("priv_cap_change") => self.priv_cap_change_count += 1,
                Some("priv_boundary_cross") => self.priv_boundary_cross_count += 1,
                Some("net_connect") => self.net_connect_count += 1,
                Some("remote_tool_exec") => self.remote_tool_exec_count += 1,
                Some("log_tamper") => self.log_tamper_count += 1,
                Some("audit_tamper") => self.audit_tamper_count += 1,
                Some("c2_suspected") => self.c2_suspected_count += 1,
                _ => {}
            }

            // Check for parity primitive events
            if event.tags.contains(&"credential_access".to_string()) {
                self.cred_access_count += 1;
            } else if event.tags.contains(&"discovery".to_string()) {
                self.discovery_exec_count += 1;
            } else if event.tags.contains(&"exfiltration".to_string()) {
                // Distinguish between archive and staging by checking fields
                if event.fields.contains_key("archive_tool") {
                    self.archive_tool_exec_count += 1;
                } else if event.fields.contains_key("path") && event.fields.contains_key("op") {
                    self.staging_write_count += 1;
                }
            } else if event.tags.contains(&"network_connection".to_string()) {
                self.net_connect_prim_count += 1;
            } else if event.tags.contains(&"persistence_change".to_string()) {
                self.persistence_change_count += 1;
            } else if event.tags.contains(&"defense_evasion".to_string()) {
                self.defense_evasion_count += 1;
            } else if event.tags.contains(&"process_injection".to_string()) {
                self.process_injection_count += 1;
            } else if event.tags.contains(&"auth_event".to_string()) {
                self.auth_event_count += 1;
            } else if event.tags.contains(&"script_exec".to_string()) {
                self.script_exec_count += 1;
            }
        }

        // Write each event to segment with EvidencePtr assigned by capture
        for mut event in events {
            // Enforce: Only capture assigns EvidencePtr (readers emit None)
            event.evidence_ptr = Some(crate::core::EvidencePtr {
                stream_id: STREAM_ID.to_string(),
                segment_id: self.segment_id,
                record_index: self.record_index,
            });

            self.write_event(&event)?;
            self.record_index += 1;

            // Rotate segment if needed
            if let Some(seg) = &self.current_segment {
                if seg.bytes_written > SEGMENT_SIZE_BYTES {
                    self.close_and_rotate_segment()?;
                }
            }
        }

        Ok(())
    }

    fn write_event(&mut self, event: &Event) -> Result<()> {
        // Ensure segment is open
        if self.current_segment.is_none() {
            self.open_segment()?;
        }

        // Serialize event to JSONL
        let json_line = format!("{}\n", serde_json::to_string(event)?);
        let bytes = json_line.as_bytes();

        // Write to segment
        if let Some(seg) = &mut self.current_segment {
            seg.file.write_all(bytes)?;
            seg.bytes_written += bytes.len();
        }

        Ok(())
    }

    fn open_segment(&mut self) -> Result<()> {
        let segment_filename = format!("segment_{:06}.jsonl", self.segment_id);
        let tmp_path = self.base_dir.join(format!("{}.tmp", segment_filename));

        let file = File::create(&tmp_path)?;

        self.current_segment = Some(SegmentWriter {
            file,
            path: tmp_path,
            bytes_written: 0,
        });

        Ok(())
    }

    fn close_and_rotate_segment(&mut self) -> Result<()> {
        if let Some(seg) = self.current_segment.take() {
            seg.file.sync_all()?;

            let final_path = self
                .base_dir
                .join(format!("segment_{:06}.jsonl", self.segment_id));
            fs::rename(&seg.path, &final_path)?;

            // Write index.json
            self.write_index(self.segment_id, seg.bytes_written)?;

            self.segment_id += 1;
            self.record_index = 0;
        }

        Ok(())
    }

    fn write_index(&self, seg_id: u64, byte_count: usize) -> Result<()> {
        let segment_path = self.base_dir.join(format!("segment_{:06}.jsonl", seg_id));
        let index_path = self
            .base_dir
            .join(format!("segment_{:06}.index.json", seg_id));

        // Compute real SHA256 of segment file
        let sha256_hash = if segment_path.exists() {
            use sha2::Digest;
            match std::fs::read(&segment_path) {
                Ok(data) => {
                    let mut hasher = Sha256::new();
                    hasher.update(&data);
                    format!("{:x}", hasher.finalize())
                }
                Err(_) => "read_error".to_string(),
            }
        } else {
            "not_found".to_string()
        };

        let index = json!({
            "segment_id": seg_id,
            "byte_count": byte_count,
            "sha256": sha256_hash,
            "timestamp": self.host.now_ms(),
        });

        let mut file = File::create(&index_path)?;
        file.write_all(serde_json::to_string_pretty(&index)?.as_bytes())?;

        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn get_ebpf_metrics(&mut self) -> crate::linux::ebpf::EbpfMetrics {
        self.ebpf_metrics.sample()
    }

    /// Write heartbeat with attack surface counters
    pub fn write_heartbeat(
        &self,
        ebpf_read: u64,
        sensors_read: u64,
        decode_failed: u64,
    ) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let transport = format!("linux_ebpf+sensors_v2");
            let heartbeat = json!({
                "ts_ms": self.host.now_ms(),
                "pid": std::process::id(),
                "segment_id": self.segment_id,
                "schema_version": 1,
                "transport": transport,
                "ebpf_read": ebpf_read,
                "sensors_read": sensors_read,
                "decode_failed": decode_failed,
                "priv_uid_change_count": self.priv_uid_change_count,
                "priv_gid_change_count": self.priv_gid_change_count,
                "priv_cap_change_count": self.priv_cap_change_count,
                "priv_boundary_cross_count": self.priv_boundary_cross_count,
                "net_connect_count": self.net_connect_count,
                "remote_tool_exec_count": self.remote_tool_exec_count,
                "log_tamper_count": self.log_tamper_count,
                "audit_tamper_count": self.audit_tamper_count,
                "c2_suspected_count": self.c2_suspected_count,
                "cred_access_count": self.cred_access_count,
                "discovery_exec_count": self.discovery_exec_count,
                "archive_tool_exec_count": self.archive_tool_exec_count,
                "staging_write_count": self.staging_write_count,
                "net_connect_prim_count": self.net_connect_prim_count,
                "persistence_change_count": self.persistence_change_count,
                "defense_evasion_count": self.defense_evasion_count,
                "process_injection_count": self.process_injection_count,
                "auth_event_count": self.auth_event_count,
                "script_exec_count": self.script_exec_count,
            });

            let heartbeat_path = self.base_dir.join("capture_heartbeat.json");
            let temp_path = self.base_dir.join("capture_heartbeat.json.tmp");

            // Write to temp file
            let json_str = serde_json::to_string(&heartbeat)?;
            let mut file = File::create(&temp_path)?;
            file.write_all(json_str.as_bytes())?;
            file.sync_all()?;

            // Atomic rename
            fs::rename(&temp_path, &heartbeat_path)?;
        }

        Ok(())
    }
}

/// Deterministically sort events by (timestamp, event_type, process_id, user_id)
fn sort_events(events: &mut Vec<Event>) {
    events.sort_by(|a, b| {
        // Primary: by timestamp (chronological)
        match a.ts_ms.cmp(&b.ts_ms) {
            std::cmp::Ordering::Equal => {
                // Secondary: by event_type
                let type_a = a.tags.first().cloned().unwrap_or_default();
                let type_b = b.tags.first().cloned().unwrap_or_default();
                match type_a.cmp(&type_b) {
                    std::cmp::Ordering::Equal => {
                        // Tertiary: by pid
                        let pid_a = a
                            .fields
                            .get(crate::core::event_keys::PROC_PID)
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let pid_b = b
                            .fields
                            .get(crate::core::event_keys::PROC_PID)
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        match pid_a.cmp(&pid_b) {
                            std::cmp::Ordering::Equal => {
                                // Quaternary: by uid
                                let uid_a = a
                                    .fields
                                    .get(crate::core::event_keys::PROC_UID)
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or(0);
                                let uid_b = b
                                    .fields
                                    .get(crate::core::event_keys::PROC_UID)
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or(0);
                                uid_a.cmp(&uid_b)
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

/// Generate minimal dedup key for derived primitives
/// Prevents duplicate primitives from same event source within one poll window
/// Key components depend on event type to capture identity uniquely
fn generate_dedup_key(event: &Event) -> String {
    let ts_ms = event.ts_ms.to_string();
    let pid = event
        .fields
        .get(crate::core::event_keys::PROC_PID)
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
        .to_string();
    let uid = event
        .fields
        .get(crate::core::event_keys::PROC_UID)
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
        .to_string();
    let event_type = event.tags.first().cloned().unwrap_or_default();

    // Build key based on event type
    if event.tags.contains(&"credential_access".to_string())
        || event.tags.contains(&"discovery".to_string())
        || event.tags.contains(&"exfiltration".to_string())
    {
        // For exec-derived: ts_ms + pid + uid + exe + first_argv
        let exe = event
            .fields
            .get(crate::core::event_keys::PROC_EXE)
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        format!("{}-{}-{}-{}-{}", ts_ms, pid, uid, event_type, exe)
    } else if event.tags.contains(&"network_connection".to_string()) {
        // For network: ts_ms + pid + uid + remote_ip + remote_port
        let remote_ip = event
            .fields
            .get(crate::core::event_keys::NET_REMOTE_IP)
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0.0");
        let remote_port = event
            .fields
            .get(crate::core::event_keys::NET_REMOTE_PORT)
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        format!(
            "{}-{}-{}-{}-{}-{}",
            ts_ms, pid, uid, event_type, remote_ip, remote_port
        )
    } else if event.tags.contains(&"persistence_change".to_string()) {
        // For persistence: ts_ms + pid + uid + location + type
        let location = event
            .fields
            .get(crate::core::event_keys::PERSIST_LOCATION)
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let persist_type = event
            .fields
            .get(crate::core::event_keys::PERSIST_TYPE)
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        format!(
            "{}-{}-{}-{}-{}-{}",
            ts_ms, pid, uid, event_type, location, persist_type
        )
    } else if event.tags.contains(&"defense_evasion".to_string()) {
        // For defense_evasion: ts_ms + pid + uid + target + action
        let target = event
            .fields
            .get(crate::core::event_keys::EVASION_TARGET)
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let action = event
            .fields
            .get(crate::core::event_keys::EVASION_ACTION)
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        format!(
            "{}-{}-{}-{}-{}-{}",
            ts_ms, pid, uid, event_type, target, action
        )
    } else if event.tags.contains(&"process_injection".to_string()) {
        // For process_injection: ts_ms + pid + uid + method + target_pid
        let method = event
            .fields
            .get(crate::core::event_keys::INJECT_METHOD)
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let target_pid = event
            .fields
            .get(crate::core::event_keys::INJECT_TARGET_PID)
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        format!(
            "{}-{}-{}-{}-{}-{}",
            ts_ms, pid, uid, event_type, method, target_pid
        )
    } else if event.tags.contains(&"auth_event".to_string()) {
        // For auth_event: ts_ms + pid + uid + user + method
        let user = event
            .fields
            .get(crate::core::event_keys::AUTH_USER)
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let method = event
            .fields
            .get(crate::core::event_keys::AUTH_METHOD)
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        format!(
            "{}-{}-{}-{}-{}-{}",
            ts_ms, pid, uid, event_type, user, method
        )
    } else if event.tags.contains(&"script_exec".to_string()) {
        // For script_exec: ts_ms + pid + uid + interpreter + script_path
        let interpreter = event
            .fields
            .get(crate::core::event_keys::SCRIPT_INTERPRETER)
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let script_path = event
            .fields
            .get(crate::core::event_keys::SCRIPT_PATH)
            .and_then(|v| v.as_str())
            .unwrap_or("inline");
        format!(
            "{}-{}-{}-{}-{}-{}",
            ts_ms, pid, uid, event_type, interpreter, script_path
        )
    } else {
        // Fallback for unknown derived types
        format!("{}-{}-{}-{}", ts_ms, pid, uid, event_type)
    }
}

/// Compute SHA256 hash of data
/// (Preserved for potential file hashing; currently unused)
#[allow(dead_code)]
fn compute_sha256(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    format!("{:x}", hasher.finalize())
}
