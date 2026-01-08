//! Linux Fact Extractor
//!
//! Converts Linux telemetry events to canonical Facts for playbook matching.
//! Supports multiple telemetry sources: auditd, eBPF probes, journald, procfs.
//!
//! This is the Linux equivalent of `os/windows/fact_extractor.rs`.

use crate::canonical::event::OrderedF32;
use crate::canonical::fact::{Fact, FactType, FieldValue, PersistType};
use crate::evidence::EvidencePtr;
use chrono::{DateTime, TimeZone, Utc};
use edr_core::Event;
use std::collections::HashMap;

use super::dns_capture::{is_dns_event, parse_dns_event};
use super::flow_aggregator::record_network_event;
use super::uid_cache::update_process_creds;

// ============================================================================
// Main Entry Point
// ============================================================================

/// Extract canonical facts from a Linux event
///
/// This is the primary entry point for the Linux fact extraction pipeline.
/// Maps Linux telemetry sources (auditd, eBPF, journald, procfs) to canonical FactType variants.
pub fn extract_facts(event: &Event) -> Vec<Fact> {
    let mut facts = Vec::new();
    let _ts = timestamp_from_ms(event.ts_ms);
    let host_id = event.host.clone();

    // Build evidence pointer with timestamp
    let evidence = match &event.evidence_ptr {
        Some(ptr) => EvidencePtr::new(
            ptr.stream_id.clone(),
            format!("{}", ptr.segment_id),
            ptr.record_index as u64,
            None,
            Some(event.ts_ms),
        ),
        None => EvidencePtr::minimal("unknown", "0", 0),
    };

    // Enrich tags from Linux telemetry sources
    let enriched_tags = enrich_tags_from_linux_source(event);
    let all_tags: Vec<&str> = event
        .tags
        .iter()
        .map(|s| s.as_str())
        .chain(enriched_tags.iter().map(|s| s.as_str()))
        .collect();

    // Route by tags to appropriate extractors
    for tag in &all_tags {
        match *tag {
            // Process events (execve, fork, clone) - includes eBPF tags
            "process" | "exec" | "execve" | "fork" | "clone" | "process_creation"
            | "process_exec" | "proc_clone" | "proc_fork" => {
                if let Some(fact) = extract_process_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // File operations - includes eBPF tags
            "file_write" | "file_create" | "file_open" | "open" | "write" | "creat"
            | "fd_write" => {
                if let Some(fact) = extract_file_write_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            "file_read" | "read" | "fd_read" => {
                if let Some(fact) = extract_file_read_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            "file_delete" | "unlink" | "rmdir" | "file_unlink" => {
                if let Some(fact) = extract_file_delete_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            "rename" | "file_rename" => {
                if let Some(fact) = extract_file_rename_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // Network events - includes eBPF tags
            "network" | "connect" | "socket" | "network_connection" | "sock_create"
            | "net_send" => {
                if let Some(fact) = extract_network_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            "accept" | "listen" | "net_accept" | "sock_bind" | "sock_listen" => {
                if let Some(fact) = extract_inbound_network_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // Authentication events (SSH, sudo, PAM)
            "auth" | "ssh" | "sudo" | "su" | "pam" | "login" | "authentication" => {
                if let Some(fact) = extract_auth_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // Persistence mechanisms
            "persistence" | "cron" | "systemd" | "init" | "rc_local" => {
                if let Some(fact) = extract_persistence_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // Privilege escalation - includes eBPF tags
            "privilege_escalation"
            | "setuid"
            | "setgid"
            | "capability"
            | "prctl"
            | "priv_setuid"
            | "priv_capset"
            | "seccomp" => {
                if let Some(fact) = extract_privilege_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // Kernel modules - includes eBPF tags
            "kernel_module"
            | "kmod"
            | "insmod"
            | "modprobe"
            | "kernel_module_load"
            | "kernel_module_delete" => {
                if let Some(fact) = extract_kernel_module_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // Module/library loading
            "module_load" | "dlopen" | "ld_preload" => {
                if let Some(fact) = extract_module_load_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // Memory operations (mmap, mprotect) - includes eBPF tags
            "memory" | "mmap" | "mprotect" | "memfd_create" | "mprotect_exec" => {
                if let Some(fact) = extract_memory_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // Ptrace/debugging
            "ptrace" | "debug" => {
                if let Some(fact) = extract_ptrace_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // BPF usage (eBPF programs loading)
            "bpf_usage" => {
                if let Some(fact) = extract_bpf_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // Container/namespace events - includes eBPF tags
            "container" | "namespace" | "cgroup" | "ns_setns" | "ns_unshare" | "fs_mount"
            | "fs_umount" | "fs_pivot_root" => {
                // Container events are handled by the signal engine directly
                // but we can extract container context for facts
                if let Some(fact) = extract_container_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // Log tampering
            "log_tamper" | "log_cleared" | "journald_clear" => {
                if let Some(fact) = extract_log_tamper_fact(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            // DNS resolution (if captured via eBPF or nscd)
            "dns" | "dns_query" | "getaddrinfo" => {
                if let Some(fact) = extract_dns_fact_impl(event, &host_id, &evidence) {
                    facts.push(fact);
                }
            }

            _ => {}
        }
    }

    // Check for DNS events in journald MESSAGE field even without explicit dns tag
    if is_dns_event(event) {
        if let Some(fact) = extract_dns_fact_impl(event, &host_id, &evidence) {
            // Avoid duplicates
            if !facts
                .iter()
                .any(|f| matches!(&f.fact_type, FactType::DnsResolve { .. }))
            {
                facts.push(fact);
            }
        }
    }

    // Secondary enrichment: detect LOLBins from Exec facts
    if let Some(exe) = event
        .fields
        .get("exe")
        .or_else(|| event.fields.get("comm"))
        .and_then(|v| v.as_str())
    {
        if is_linux_lolbin(exe) {
            // Already captured by process extraction, add enrichment tags
        }
    }

    facts
}

// ============================================================================
// Tag Enrichment
// ============================================================================

/// Enrich event tags based on Linux telemetry source
///
/// Maps auditd syscall numbers, eBPF probe types, journald units to detection tags.
pub fn enrich_tags_from_linux_source(event: &Event) -> Vec<String> {
    let mut tags = Vec::new();

    // === AUDITD ENRICHMENT ===
    if let Some(_syscall) = event
        .fields
        .get("syscall")
        .or_else(|| event.fields.get("audit.syscall"))
        .and_then(|v| v.as_str().or_else(|| v.as_u64().map(|_| "")))
    {
        // Map syscall names/numbers to tags
        let syscall_str = event
            .fields
            .get("syscall")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        match syscall_str {
            "execve" | "execveat" => tags.push("exec".to_string()),
            "fork" | "clone" | "clone3" => tags.push("fork".to_string()),
            "open" | "openat" | "openat2" => tags.push("open".to_string()),
            "write" | "pwrite64" | "writev" => tags.push("write".to_string()),
            "read" | "pread64" | "readv" => tags.push("read".to_string()),
            "unlink" | "unlinkat" => tags.push("unlink".to_string()),
            "rename" | "renameat" | "renameat2" => tags.push("rename".to_string()),
            "connect" => tags.push("connect".to_string()),
            "socket" => tags.push("socket".to_string()),
            "accept" | "accept4" => tags.push("accept".to_string()),
            "bind" | "listen" => tags.push("listen".to_string()),
            "mmap" | "mmap2" => tags.push("mmap".to_string()),
            "mprotect" => tags.push("mprotect".to_string()),
            "memfd_create" => tags.push("memfd_create".to_string()),
            "ptrace" => tags.push("ptrace".to_string()),
            "init_module" | "finit_module" => tags.push("kmod".to_string()),
            "setuid" | "setgid" | "setreuid" | "setregid" => {
                tags.push("privilege_escalation".to_string())
            }
            "prctl" => {
                // Check for capability manipulation
                if let Some(arg) = event.fields.get("a0").and_then(|v| v.as_u64()) {
                    if arg == 24 || arg == 25 {
                        // PR_CAPBSET_READ, PR_CAPBSET_DROP
                        tags.push("capability".to_string());
                    }
                }
            }
            _ => {}
        }
    }

    // === AUDIT TYPE ENRICHMENT ===
    if let Some(audit_type) = event
        .fields
        .get("audit.type")
        .or_else(|| event.fields.get("type"))
        .and_then(|v| v.as_str())
    {
        match audit_type {
            "EXECVE" => tags.push("exec".to_string()),
            "SYSCALL" => {} // Already handled by syscall field
            "PATH" => tags.push("file_path".to_string()),
            "CWD" => {}
            "PROCTITLE" => {}
            "USER_AUTH" | "USER_ACCT" => tags.push("auth".to_string()),
            "CRED_ACQ" | "CRED_DISP" => tags.push("auth".to_string()),
            "USER_LOGIN" | "USER_START" | "USER_END" => tags.push("login".to_string()),
            "USER_CMD" => tags.push("sudo".to_string()),
            "SERVICE_START" | "SERVICE_STOP" => tags.push("systemd".to_string()),
            "ANOM_ABEND" => tags.push("crash".to_string()),
            _ => {}
        }
    }

    // === JOURNALD/SYSLOG ENRICHMENT ===
    if let Some(unit) = event
        .fields
        .get("_SYSTEMD_UNIT")
        .or_else(|| event.fields.get("systemd.unit"))
        .and_then(|v| v.as_str())
    {
        if unit.contains("ssh") {
            tags.push("ssh".to_string());
        } else if unit.contains("sudo") {
            tags.push("sudo".to_string());
        } else if unit.contains("cron") {
            tags.push("cron".to_string());
        } else if unit.contains("docker") || unit.contains("containerd") {
            tags.push("container".to_string());
        }
    }

    // === eBPF PROBE TYPE ENRICHMENT ===
    if let Some(probe_type) = event
        .fields
        .get("ebpf.probe")
        .or_else(|| event.fields.get("probe_type"))
        .and_then(|v| v.as_str())
    {
        match probe_type {
            "tracepoint:syscalls:sys_enter_execve" | "tracepoint:sched:sched_process_exec" => {
                tags.push("exec".to_string())
            }
            "tracepoint:syscalls:sys_enter_connect" => tags.push("connect".to_string()),
            "tracepoint:syscalls:sys_enter_open" | "tracepoint:syscalls:sys_enter_openat" => {
                tags.push("open".to_string())
            }
            "kprobe:tcp_connect" | "kprobe:tcp_v4_connect" => tags.push("network".to_string()),
            "kprobe:security_file_open" => tags.push("file_open".to_string()),
            _ => {}
        }
    }

    // === SSHD AUTH ENRICHMENT ===
    if let Some(msg) = event
        .fields
        .get("MESSAGE")
        .or_else(|| event.fields.get("message"))
        .and_then(|v| v.as_str())
    {
        let msg_lower = msg.to_lowercase();
        if msg_lower.contains("accepted") || msg_lower.contains("failed password") {
            tags.push("ssh".to_string());
            tags.push("auth".to_string());
        } else if msg_lower.contains("sudo:") {
            tags.push("sudo".to_string());
            tags.push("auth".to_string());
        } else if msg_lower.contains("pam_unix") {
            tags.push("pam".to_string());
            tags.push("auth".to_string());
        }
    }

    tags
}

// ============================================================================
// Fact Extractors
// ============================================================================

/// Extract process execution fact
pub fn extract_process_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    // Get executable path
    let exe_path = event
        .fields
        .get("exe")
        .or_else(|| event.fields.get("comm"))
        .or_else(|| event.fields.get("audit.exe"))
        .or_else(|| event.fields.get("_COMM"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    // Get command line
    let cmdline = event
        .fields
        .get("cmdline")
        .or_else(|| event.fields.get("audit.cmdline"))
        .or_else(|| event.fields.get("proctitle"))
        .or_else(|| event.fields.get("PROCTITLE"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Get process key
    let pid = event
        .fields
        .get("pid")
        .or_else(|| event.fields.get("audit.pid"))
        .or_else(|| event.fields.get("_PID"))
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .unwrap_or(0);

    let proc_key = event
        .proc_key
        .clone()
        .unwrap_or_else(|| format!("proc_{}_{}", host_id, pid));

    // Get parent process info
    let ppid = event
        .fields
        .get("ppid")
        .or_else(|| event.fields.get("audit.ppid"))
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        });

    // Build scope key
    let scope_key = build_scope_key(event);

    // Create fact type
    let fact_type = FactType::Exec {
        proc_key: proc_key.clone(),
        exe_hash: event
            .fields
            .get("exe_hash")
            .or_else(|| event.fields.get("sha256"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        exe_path,
        signer: None, // Linux doesn't have signing like Windows
        cmdline,
    };

    // Build additional fields
    let mut fields = HashMap::new();

    // UID/GID info
    if let Some(uid) = event
        .fields
        .get("uid")
        .or_else(|| event.fields.get("audit.uid"))
        .or_else(|| event.fields.get("_UID"))
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
    {
        fields.insert("uid".to_string(), FieldValue::UInt(uid));
    }

    if let Some(gid) = event
        .fields
        .get("gid")
        .or_else(|| event.fields.get("audit.gid"))
        .or_else(|| event.fields.get("_GID"))
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
    {
        fields.insert("gid".to_string(), FieldValue::UInt(gid));
    }

    if let Some(euid) = event
        .fields
        .get("euid")
        .or_else(|| event.fields.get("audit.euid"))
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
    {
        fields.insert("euid".to_string(), FieldValue::UInt(euid));
    }

    // CWD
    if let Some(cwd) = event
        .fields
        .get("cwd")
        .or_else(|| event.fields.get("audit.cwd"))
        .and_then(|v| v.as_str())
    {
        fields.insert("cwd".to_string(), FieldValue::string(cwd));
    }

    // Parent info
    if let Some(ppid_val) = ppid {
        fields.insert("ppid".to_string(), FieldValue::UInt(ppid_val));
    }

    if let Some(parent_exe) = event
        .fields
        .get("parent_exe")
        .or_else(|| event.fields.get("pexe"))
        .and_then(|v| v.as_str())
    {
        fields.insert("parent_exe".to_string(), FieldValue::string(parent_exe));
    }

    // TTY
    if let Some(tty) = event.fields.get("tty").and_then(|v| v.as_str()) {
        fields.insert("tty".to_string(), FieldValue::string(tty));
    }

    // Build fact
    let fact_id = Fact::compute_fact_id(host_id, &scope_key, &fact_type, event.ts_ms);

    Some(Fact {
        fact_id,
        ts: event.ts_ms,
        host_id: host_id.to_string(),
        scope_key,
        fact_type,
        fields,
        evidence_ptrs: vec![evidence.clone()],
        conflict_set_id: None,
        visibility_gaps: Vec::new(),
    })
}

/// Extract file write/create fact
pub fn extract_file_write_fact(
    event: &Event,
    host_id: &str,
    evidence: &EvidencePtr,
) -> Option<Fact> {
    let path = event
        .fields
        .get("path")
        .or_else(|| event.fields.get("audit.path"))
        .or_else(|| event.fields.get("filename"))
        .or_else(|| event.fields.get("name"))
        .and_then(|v| v.as_str())?
        .to_string();

    let pid = event
        .fields
        .get("pid")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let proc_key = event
        .proc_key
        .clone()
        .unwrap_or_else(|| format!("proc_{}_{}", host_id, pid));

    let scope_key = build_scope_key(event);

    let bytes_written = event
        .fields
        .get("bytes")
        .or_else(|| event.fields.get("size"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let inode = event
        .fields
        .get("inode")
        .or_else(|| event.fields.get("audit.inode"))
        .and_then(|v| v.as_u64());

    let fact_type = FactType::WritePath {
        proc_key,
        path,
        inode,
        bytes_written,
        entropy: event
            .fields
            .get("entropy")
            .and_then(|v| v.as_f64())
            .map(|f| OrderedF32(f as f32)),
    };

    let fact_id = Fact::compute_fact_id(host_id, &scope_key, &fact_type, event.ts_ms);

    Some(Fact {
        fact_id,
        ts: event.ts_ms,
        host_id: host_id.to_string(),
        scope_key,
        fact_type,
        fields: HashMap::new(),
        evidence_ptrs: vec![evidence.clone()],
        conflict_set_id: None,
        visibility_gaps: Vec::new(),
    })
}

/// Extract file read fact
pub fn extract_file_read_fact(
    event: &Event,
    host_id: &str,
    evidence: &EvidencePtr,
) -> Option<Fact> {
    let path = event
        .fields
        .get("path")
        .or_else(|| event.fields.get("audit.path"))
        .or_else(|| event.fields.get("filename"))
        .and_then(|v| v.as_str())?
        .to_string();

    let pid = event
        .fields
        .get("pid")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let proc_key = event
        .proc_key
        .clone()
        .unwrap_or_else(|| format!("proc_{}_{}", host_id, pid));

    let scope_key = build_scope_key(event);

    let bytes_read = event
        .fields
        .get("bytes")
        .or_else(|| event.fields.get("size"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let fact_type = FactType::ReadPath {
        proc_key,
        path,
        inode: event.fields.get("inode").and_then(|v| v.as_u64()),
        bytes_read,
    };

    let fact_id = Fact::compute_fact_id(host_id, &scope_key, &fact_type, event.ts_ms);

    Some(Fact {
        fact_id,
        ts: event.ts_ms,
        host_id: host_id.to_string(),
        scope_key,
        fact_type,
        fields: HashMap::new(),
        evidence_ptrs: vec![evidence.clone()],
        conflict_set_id: None,
        visibility_gaps: Vec::new(),
    })
}

/// Extract file delete fact
pub fn extract_file_delete_fact(
    event: &Event,
    host_id: &str,
    evidence: &EvidencePtr,
) -> Option<Fact> {
    let path = event
        .fields
        .get("path")
        .or_else(|| event.fields.get("audit.path"))
        .or_else(|| event.fields.get("filename"))
        .and_then(|v| v.as_str())?
        .to_string();

    let pid = event
        .fields
        .get("pid")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let proc_key = event
        .proc_key
        .clone()
        .unwrap_or_else(|| format!("proc_{}_{}", host_id, pid));

    let scope_key = build_scope_key(event);

    let fact_type = FactType::DeletePath { proc_key, path };

    let fact_id = Fact::compute_fact_id(host_id, &scope_key, &fact_type, event.ts_ms);

    Some(Fact {
        fact_id,
        ts: event.ts_ms,
        host_id: host_id.to_string(),
        scope_key,
        fact_type,
        fields: HashMap::new(),
        evidence_ptrs: vec![evidence.clone()],
        conflict_set_id: None,
        visibility_gaps: Vec::new(),
    })
}

/// Extract file rename fact (emits as write to new path)
pub fn extract_file_rename_fact(
    event: &Event,
    host_id: &str,
    evidence: &EvidencePtr,
) -> Option<Fact> {
    // For rename, use destination path
    let path = event
        .fields
        .get("dest")
        .or_else(|| event.fields.get("newpath"))
        .or_else(|| event.fields.get("path"))
        .and_then(|v| v.as_str())?
        .to_string();

    let pid = event
        .fields
        .get("pid")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let proc_key = event
        .proc_key
        .clone()
        .unwrap_or_else(|| format!("proc_{}_{}", host_id, pid));

    let scope_key = build_scope_key(event);

    // Store old path in fields
    let mut fields = HashMap::new();
    if let Some(old_path) = event
        .fields
        .get("src")
        .or_else(|| event.fields.get("oldpath"))
        .and_then(|v| v.as_str())
    {
        fields.insert("old_path".to_string(), FieldValue::string(old_path));
    }

    let fact_type = FactType::CreatePath {
        proc_key,
        path,
        inode: event.fields.get("inode").and_then(|v| v.as_u64()),
    };

    let fact_id = Fact::compute_fact_id(host_id, &scope_key, &fact_type, event.ts_ms);

    Some(Fact {
        fact_id,
        ts: event.ts_ms,
        host_id: host_id.to_string(),
        scope_key,
        fact_type,
        fields,
        evidence_ptrs: vec![evidence.clone()],
        conflict_set_id: None,
        visibility_gaps: Vec::new(),
    })
}

/// Extract outbound network connection fact
pub fn extract_network_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    let dst_ip = event
        .fields
        .get("dest_ip")
        .or_else(|| event.fields.get("dst_ip"))
        .or_else(|| event.fields.get("addr"))
        .or_else(|| event.fields.get("saddr"))
        .and_then(|v| v.as_str())?
        .to_string();

    let dst_port = event
        .fields
        .get("dest_port")
        .or_else(|| event.fields.get("dst_port"))
        .or_else(|| event.fields.get("port"))
        .or_else(|| event.fields.get("dport"))
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .unwrap_or(0) as u16;

    let pid = event
        .fields
        .get("pid")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let proc_key = event
        .proc_key
        .clone()
        .unwrap_or_else(|| format!("proc_{}_{}", host_id, pid));

    let scope_key = build_scope_key(event);

    let protocol = event
        .fields
        .get("protocol")
        .or_else(|| event.fields.get("proto"))
        .and_then(|v| v.as_str())
        .unwrap_or("tcp")
        .to_string();

    // Get local endpoint info for net_key
    let local_ip = event
        .fields
        .get("local_ip")
        .or_else(|| event.fields.get("src_ip"))
        .and_then(|v| v.as_str())
        .unwrap_or("0.0.0.0");

    let local_port = event
        .fields
        .get("local_port")
        .or_else(|| event.fields.get("sport"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u16;

    // Build net_key for playbook matching: local_ip:local_port->remote_ip:remote_port/protocol
    let net_key = format!(
        "{}:{}->{}:{}/{}",
        local_ip, local_port, dst_ip, dst_port, protocol
    );

    // Get bytes transferred
    let bytes_sent = event
        .fields
        .get("bytes_sent")
        .or_else(|| event.fields.get("bytes_out"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let bytes_recv = event
        .fields
        .get("bytes_recv")
        .or_else(|| event.fields.get("bytes_in"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let total_bytes = bytes_sent + bytes_recv;

    // Record network event for flow aggregation
    let agg_fields = record_network_event(
        local_ip,
        local_port,
        &dst_ip,
        dst_port,
        &protocol,
        &proc_key,
        event.ts_ms,
        if total_bytes > 0 {
            Some(total_bytes)
        } else {
            None
        },
    );

    let fact_type = FactType::OutboundConnect {
        proc_key: proc_key.clone(),
        dst_ip: dst_ip.clone(),
        dst_port,
        protocol: protocol.clone(),
        sock_key: event
            .fields
            .get("sock_key")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
    };

    let fact_id = Fact::compute_fact_id(host_id, &scope_key, &fact_type, event.ts_ms);

    // Build fields with net_key and aggregation data
    let mut fields = HashMap::new();
    fields.insert("net_key".to_string(), FieldValue::String(net_key));
    fields.insert("protocol".to_string(), FieldValue::String(protocol));

    // Add __agg.* fields from flow aggregator for playbook matching
    fields.insert(
        "__agg.duration_sec".to_string(),
        FieldValue::Float(agg_fields.duration_sec as f64),
    );
    fields.insert(
        "__agg.connect_count".to_string(),
        FieldValue::UInt(agg_fields.connect_count as u64),
    );
    fields.insert(
        "__agg.bytes_total".to_string(),
        FieldValue::UInt(agg_fields.bytes_total),
    );
    fields.insert(
        "__agg.kind".to_string(),
        FieldValue::String(agg_fields.kind),
    );

    if bytes_sent > 0 {
        fields.insert("bytes_sent".to_string(), FieldValue::UInt(bytes_sent));
    }
    if bytes_recv > 0 {
        fields.insert("bytes_recv".to_string(), FieldValue::UInt(bytes_recv));
    }

    // Add identity_key based on UID
    if let Some(uid) = event.fields.get("uid").and_then(|v| v.as_u64()) {
        fields.insert(
            "identity_key".to_string(),
            FieldValue::String(format!("uid:{}", uid)),
        );
    }

    Some(Fact {
        fact_id,
        ts: event.ts_ms,
        host_id: host_id.to_string(),
        scope_key,
        fact_type,
        fields,
        evidence_ptrs: vec![evidence.clone()],
        conflict_set_id: None,
        visibility_gaps: Vec::new(),
    })
}

/// Extract inbound network connection fact
pub fn extract_inbound_network_fact(
    event: &Event,
    host_id: &str,
    evidence: &EvidencePtr,
) -> Option<Fact> {
    let src_ip = event
        .fields
        .get("src_ip")
        .or_else(|| event.fields.get("source_ip"))
        .or_else(|| event.fields.get("raddr"))
        .and_then(|v| v.as_str())?
        .to_string();

    let src_port = event
        .fields
        .get("src_port")
        .or_else(|| event.fields.get("source_port"))
        .or_else(|| event.fields.get("sport"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u16;

    let pid = event
        .fields
        .get("pid")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let proc_key = event
        .proc_key
        .clone()
        .unwrap_or_else(|| format!("proc_{}_{}", host_id, pid));

    let scope_key = build_scope_key(event);

    let protocol = event
        .fields
        .get("protocol")
        .or_else(|| event.fields.get("proto"))
        .and_then(|v| v.as_str())
        .unwrap_or("tcp")
        .to_string();

    let fact_type = FactType::InboundAccept {
        proc_key,
        src_ip,
        src_port,
        protocol,
        sock_key: None,
    };

    let fact_id = Fact::compute_fact_id(host_id, &scope_key, &fact_type, event.ts_ms);

    Some(Fact {
        fact_id,
        ts: event.ts_ms,
        host_id: host_id.to_string(),
        scope_key,
        fact_type,
        fields: HashMap::new(),
        evidence_ptrs: vec![evidence.clone()],
        conflict_set_id: None,
        visibility_gaps: Vec::new(),
    })
}

/// Extract authentication fact (SSH, sudo, PAM)
pub fn extract_auth_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    // Determine auth type from tags or fields
    let auth_type = if event.tags.contains(&"ssh".to_string()) {
        "ssh"
    } else if event.tags.contains(&"sudo".to_string()) {
        "sudo"
    } else if event.tags.contains(&"su".to_string()) {
        "su"
    } else if event.tags.contains(&"pam".to_string()) {
        "pam"
    } else {
        event
            .fields
            .get("auth_type")
            .or_else(|| event.fields.get("pam_type"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
    }
    .to_string();

    // Determine success/failure
    let success = event
        .fields
        .get("result")
        .or_else(|| event.fields.get("res"))
        .or_else(|| event.fields.get("success"))
        .and_then(|v| {
            v.as_str()
                .map(|s| s == "success" || s == "1" || s.to_lowercase() == "true")
                .or_else(|| v.as_bool())
        })
        .unwrap_or_else(|| {
            // Check message for success/failure patterns
            event
                .fields
                .get("MESSAGE")
                .or_else(|| event.fields.get("message"))
                .and_then(|v| v.as_str())
                .map(|msg| {
                    let msg_lower = msg.to_lowercase();
                    msg_lower.contains("accepted") || msg_lower.contains("opened session")
                })
                .unwrap_or(false)
        });

    // Get user
    let user_key = event
        .identity_key
        .clone()
        .or_else(|| {
            event
                .fields
                .get("user")
                .or_else(|| event.fields.get("acct"))
                .or_else(|| event.fields.get("auid"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "unknown".to_string());

    // Get source IP (for SSH)
    let source_ip = event
        .fields
        .get("source_ip")
        .or_else(|| event.fields.get("addr"))
        .or_else(|| event.fields.get("hostname"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let scope_key = format!("user:{}", user_key);

    let fact_type = FactType::AuthEvent {
        user_key: user_key.clone(),
        auth_type,
        success,
        source_ip,
    };

    let fact_id = Fact::compute_fact_id(host_id, &scope_key, &fact_type, event.ts_ms);

    // Additional fields
    let mut fields = HashMap::new();
    if let Some(terminal) = event.fields.get("terminal").and_then(|v| v.as_str()) {
        fields.insert("terminal".to_string(), FieldValue::string(terminal));
    }

    Some(Fact {
        fact_id,
        ts: event.ts_ms,
        host_id: host_id.to_string(),
        scope_key,
        fact_type,
        fields,
        evidence_ptrs: vec![evidence.clone()],
        conflict_set_id: None,
        visibility_gaps: Vec::new(),
    })
}

/// Extract persistence mechanism fact
pub fn extract_persistence_fact(
    event: &Event,
    host_id: &str,
    evidence: &EvidencePtr,
) -> Option<Fact> {
    let path = event
        .fields
        .get("path")
        .or_else(|| event.fields.get("unit"))
        .or_else(|| event.fields.get("filename"))
        .and_then(|v| v.as_str())?
        .to_string();

    let pid = event
        .fields
        .get("pid")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let proc_key = event
        .proc_key
        .clone()
        .unwrap_or_else(|| format!("proc_{}_{}", host_id, pid));

    let scope_key = build_scope_key(event);

    // Determine persistence type
    let persist_type = if event.tags.contains(&"cron".to_string()) || path.contains("/cron") {
        let schedule = event
            .fields
            .get("schedule")
            .and_then(|v| v.as_str())
            .unwrap_or("* * * * *")
            .to_string();
        PersistType::CronJob { schedule }
    } else if event.tags.contains(&"systemd".to_string()) || path.contains(".service") {
        let unit_name = path
            .rsplit('/')
            .next()
            .unwrap_or(&path)
            .trim_end_matches(".service")
            .to_string();
        PersistType::SystemdUnit { unit_name }
    } else {
        PersistType::Other {
            description: "Linux persistence".to_string(),
        }
    };

    let fact_type = FactType::PersistArtifact {
        proc_key,
        persist_type,
        path,
        enabled: true,
    };

    let fact_id = Fact::compute_fact_id(host_id, &scope_key, &fact_type, event.ts_ms);

    Some(Fact {
        fact_id,
        ts: event.ts_ms,
        host_id: host_id.to_string(),
        scope_key,
        fact_type,
        fields: HashMap::new(),
        evidence_ptrs: vec![evidence.clone()],
        conflict_set_id: None,
        visibility_gaps: Vec::new(),
    })
}

/// Extract privilege escalation fact
pub fn extract_privilege_fact(
    event: &Event,
    host_id: &str,
    evidence: &EvidencePtr,
) -> Option<Fact> {
    let pid = event
        .fields
        .get("pid")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    let proc_key = event
        .proc_key
        .clone()
        .unwrap_or_else(|| format!("proc_{}_{}", host_id, pid));

    let scope_key = build_scope_key(event);

    // Get current credentials from event
    let uid = event
        .fields
        .get("uid")
        .and_then(|v| v.as_u64())
        .unwrap_or(1000) as u32;

    let euid = event
        .fields
        .get("euid")
        .and_then(|v| v.as_u64())
        .unwrap_or(uid as u64) as u32;

    let gid = event
        .fields
        .get("gid")
        .and_then(|v| v.as_u64())
        .unwrap_or(1000) as u32;

    let egid = event
        .fields
        .get("egid")
        .and_then(|v| v.as_u64())
        .unwrap_or(gid as u64) as u32;

    let caps = event
        .fields
        .get("caps_effective")
        .or_else(|| event.fields.get("cap"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    // Use UID cache to get before/after credential change
    let cred_change = update_process_creds(pid, uid, euid, gid, egid, caps);

    let fact_type = FactType::PrivilegeBoundary {
        proc_key: proc_key.clone(),
        uid_before: cred_change.uid_before,
        uid_after: cred_change.uid_after,
        caps_added: cred_change.caps_added.clone(),
        caps_removed: cred_change.caps_removed.clone(),
    };

    let fact_id = Fact::compute_fact_id(host_id, &scope_key, &fact_type, event.ts_ms);

    // Build additional fields with credential change details
    let mut fields = HashMap::new();
    fields.insert(
        "uid_before".to_string(),
        FieldValue::UInt(cred_change.uid_before as u64),
    );
    fields.insert(
        "uid_after".to_string(),
        FieldValue::UInt(cred_change.uid_after as u64),
    );
    fields.insert(
        "euid_before".to_string(),
        FieldValue::UInt(cred_change.euid_before as u64),
    );
    fields.insert(
        "euid_after".to_string(),
        FieldValue::UInt(cred_change.euid_after as u64),
    );

    // Add identity_key for correlation
    fields.insert(
        "identity_key".to_string(),
        FieldValue::String(format!(
            "uid:{}|euid:{}",
            cred_change.uid_after, cred_change.euid_after
        )),
    );

    // Flag if this is an escalation to root
    if cred_change.uid_after == 0 || cred_change.euid_after == 0 {
        fields.insert("escalated_to_root".to_string(), FieldValue::Bool(true));
    }

    Some(Fact {
        fact_id,
        ts: event.ts_ms,
        host_id: host_id.to_string(),
        scope_key,
        fact_type,
        fields,
        evidence_ptrs: vec![evidence.clone()],
        conflict_set_id: None,
        visibility_gaps: Vec::new(),
    })
}

/// Extract kernel module load fact
pub fn extract_kernel_module_fact(
    event: &Event,
    host_id: &str,
    evidence: &EvidencePtr,
) -> Option<Fact> {
    let module_name = event
        .fields
        .get("module")
        .or_else(|| event.fields.get("name"))
        .or_else(|| event.fields.get("module_name"))
        .and_then(|v| v.as_str())?
        .to_string();

    let module_path = event
        .fields
        .get("path")
        .or_else(|| event.fields.get("module_path"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let scope_key = format!("kmod:{}", module_name);

    // Modules loaded via init_module are unsigned unless from kernel tree
    let is_signed = event
        .fields
        .get("signed")
        .and_then(|v| v.as_bool())
        .or_else(|| {
            module_path.as_ref().map(|p| {
                p.starts_with("/lib/modules/") && !p.contains("/extra/") && !p.contains("/updates/")
            })
        });

    let fact_type = FactType::KernelModule {
        module_name,
        module_path,
        is_signed,
    };

    let fact_id = Fact::compute_fact_id(host_id, &scope_key, &fact_type, event.ts_ms);

    Some(Fact {
        fact_id,
        ts: event.ts_ms,
        host_id: host_id.to_string(),
        scope_key,
        fact_type,
        fields: HashMap::new(),
        evidence_ptrs: vec![evidence.clone()],
        conflict_set_id: None,
        visibility_gaps: Vec::new(),
    })
}

/// Extract shared library/module load fact
pub fn extract_module_load_fact(
    event: &Event,
    host_id: &str,
    evidence: &EvidencePtr,
) -> Option<Fact> {
    let module_path = event
        .fields
        .get("path")
        .or_else(|| event.fields.get("library"))
        .or_else(|| event.fields.get("filename"))
        .and_then(|v| v.as_str())?
        .to_string();

    let pid = event
        .fields
        .get("pid")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let proc_key = event
        .proc_key
        .clone()
        .unwrap_or_else(|| format!("proc_{}_{}", host_id, pid));

    let scope_key = build_scope_key(event);

    let fact_type = FactType::ModuleLoad {
        proc_key,
        module_path,
        module_hash: event
            .fields
            .get("hash")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        is_signed: None, // Linux shared libs typically aren't signed
    };

    let fact_id = Fact::compute_fact_id(host_id, &scope_key, &fact_type, event.ts_ms);

    Some(Fact {
        fact_id,
        ts: event.ts_ms,
        host_id: host_id.to_string(),
        scope_key,
        fact_type,
        fields: HashMap::new(),
        evidence_ptrs: vec![evidence.clone()],
        conflict_set_id: None,
        visibility_gaps: Vec::new(),
    })
}

/// Extract memory protection change fact (mprotect RWX)
pub fn extract_memory_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    let pid = event
        .fields
        .get("pid")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let proc_key = event
        .proc_key
        .clone()
        .unwrap_or_else(|| format!("proc_{}_{}", host_id, pid));

    let scope_key = build_scope_key(event);

    let addr = event
        .fields
        .get("addr")
        .or_else(|| event.fields.get("start"))
        .and_then(|v| {
            v.as_u64().or_else(|| {
                v.as_str()
                    .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            })
        })
        .unwrap_or(0);

    let size = event
        .fields
        .get("len")
        .or_else(|| event.fields.get("size"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let prot_after = event
        .fields
        .get("prot")
        .or_else(|| event.fields.get("protection"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    let fact_type = FactType::MemWX {
        proc_key,
        addr,
        size,
        prot_before: 0, // Not always available
        prot_after,
    };

    let fact_id = Fact::compute_fact_id(host_id, &scope_key, &fact_type, event.ts_ms);

    Some(Fact {
        fact_id,
        ts: event.ts_ms,
        host_id: host_id.to_string(),
        scope_key,
        fact_type,
        fields: HashMap::new(),
        evidence_ptrs: vec![evidence.clone()],
        conflict_set_id: None,
        visibility_gaps: Vec::new(),
    })
}

/// Extract ptrace/debug attachment fact
pub fn extract_ptrace_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    let source_pid = event
        .fields
        .get("pid")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let target_pid = event
        .fields
        .get("target_pid")
        .or_else(|| event.fields.get("data"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    if target_pid == 0 {
        return None;
    }

    let source_proc_key = event
        .proc_key
        .clone()
        .unwrap_or_else(|| format!("proc_{}_{}", host_id, source_pid));

    let target_proc_key = format!("proc_{}_{}", host_id, target_pid);

    let scope_key = build_scope_key(event);

    let fact_type = FactType::DebugAttach {
        source_proc_key,
        target_proc_key,
    };

    let fact_id = Fact::compute_fact_id(host_id, &scope_key, &fact_type, event.ts_ms);

    Some(Fact {
        fact_id,
        ts: event.ts_ms,
        host_id: host_id.to_string(),
        scope_key,
        fact_type,
        fields: HashMap::new(),
        evidence_ptrs: vec![evidence.clone()],
        conflict_set_id: None,
        visibility_gaps: Vec::new(),
    })
}

/// Extract BPF program loading fact
///
/// BPF program loading is a common persistence/evasion technique
pub fn extract_bpf_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    let pid = event
        .fields
        .get("pid")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let _proc_key = event
        .proc_key
        .clone()
        .unwrap_or_else(|| format!("proc_{}_{}", host_id, pid));

    let scope_key = build_scope_key(event);

    // BPF command type from aux_u32
    let bpf_cmd = event
        .fields
        .get("aux_u32")
        .or_else(|| event.fields.get("bpf_cmd"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let cmd_name = match bpf_cmd {
        0 => "BPF_MAP_CREATE",
        5 => "BPF_PROG_LOAD",
        25 => "BPF_BTF_LOAD",
        _ => "BPF_UNKNOWN",
    };

    // Treat as suspicious activity similar to KernelModule
    let fact_type = FactType::KernelModule {
        module_name: format!("bpf:{}", cmd_name),
        module_path: None,
        is_signed: Some(false), // BPF programs are not signed
    };

    let fact_id = Fact::compute_fact_id(host_id, &scope_key, &fact_type, event.ts_ms);

    let mut fields = HashMap::new();
    fields.insert(
        "bpf_cmd".to_string(),
        FieldValue::String(cmd_name.to_string()),
    );
    fields.insert("bpf_cmd_id".to_string(), FieldValue::UInt(bpf_cmd));

    // Add identity_key for correlation
    if let Some(uid) = event.fields.get("uid").and_then(|v| v.as_u64()) {
        fields.insert(
            "identity_key".to_string(),
            FieldValue::String(format!("uid:{}", uid)),
        );
    }

    Some(Fact {
        fact_id,
        ts: event.ts_ms,
        host_id: host_id.to_string(),
        scope_key,
        fact_type,
        fields,
        evidence_ptrs: vec![evidence.clone()],
        conflict_set_id: None,
        visibility_gaps: Vec::new(),
    })
}

/// Extract container/namespace fact
///
/// Tracks namespace changes, container escapes, mount operations
pub fn extract_container_fact(
    event: &Event,
    host_id: &str,
    evidence: &EvidencePtr,
) -> Option<Fact> {
    let pid = event
        .fields
        .get("pid")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let proc_key = event
        .proc_key
        .clone()
        .unwrap_or_else(|| format!("proc_{}_{}", host_id, pid));

    let scope_key = build_scope_key(event);

    // Determine operation type from tags
    let operation = event
        .tags
        .iter()
        .find_map(|t| match t.as_str() {
            "ns_setns" => Some("setns"),
            "ns_unshare" => Some("unshare"),
            "fs_mount" => Some("mount"),
            "fs_umount" => Some("umount"),
            "fs_pivot_root" => Some("pivot_root"),
            _ => None,
        })
        .unwrap_or("namespace");

    // Get path/target from event
    let target = event
        .fields
        .get("path")
        .or_else(|| event.fields.get("path2"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Get flags
    let flags = event
        .fields
        .get("flags")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    // Build the path for PersistArtifact
    let artifact_path = if target.is_empty() {
        format!("namespace:{}", operation)
    } else {
        target.clone()
    };

    // Use PersistArtifact to track suspicious namespace/mount operations
    let fact_type = FactType::PersistArtifact {
        proc_key: proc_key.clone(),
        persist_type: PersistType::Other {
            description: format!("namespace:{}", operation),
        },
        path: artifact_path,
        enabled: true,
    };

    let fact_id = Fact::compute_fact_id(host_id, &scope_key, &fact_type, event.ts_ms);

    let mut fields = HashMap::new();
    fields.insert(
        "operation".to_string(),
        FieldValue::String(operation.to_string()),
    );
    fields.insert("flags".to_string(), FieldValue::UInt(flags));
    if !target.is_empty() {
        fields.insert("target".to_string(), FieldValue::String(target));
    }

    // Add identity_key for correlation
    if let Some(uid) = event.fields.get("uid").and_then(|v| v.as_u64()) {
        fields.insert(
            "identity_key".to_string(),
            FieldValue::String(format!("uid:{}", uid)),
        );
    }

    Some(Fact {
        fact_id,
        ts: event.ts_ms,
        host_id: host_id.to_string(),
        scope_key,
        fact_type,
        fields,
        evidence_ptrs: vec![evidence.clone()],
        conflict_set_id: None,
        visibility_gaps: Vec::new(),
    })
}

/// Extract log tampering fact
pub fn extract_log_tamper_fact(
    event: &Event,
    host_id: &str,
    evidence: &EvidencePtr,
) -> Option<Fact> {
    let log_name = event
        .fields
        .get("log")
        .or_else(|| event.fields.get("file"))
        .or_else(|| event.fields.get("unit"))
        .and_then(|v| v.as_str())
        .unwrap_or("syslog")
        .to_string();

    let pid = event.fields.get("pid").and_then(|v| v.as_u64());

    let proc_key = pid.map(|p| {
        event
            .proc_key
            .clone()
            .unwrap_or_else(|| format!("proc_{}_{}", host_id, p))
    });

    let scope_key = format!("log:{}", log_name);

    let fact_type = FactType::LogCleared { proc_key, log_name };

    let fact_id = Fact::compute_fact_id(host_id, &scope_key, &fact_type, event.ts_ms);

    Some(Fact {
        fact_id,
        ts: event.ts_ms,
        host_id: host_id.to_string(),
        scope_key,
        fact_type,
        fields: HashMap::new(),
        evidence_ptrs: vec![evidence.clone()],
        conflict_set_id: None,
        visibility_gaps: Vec::new(),
    })
}

/// Extract DNS query fact
///
/// Handles multiple sources:
/// - Direct eBPF DNS capture
/// - journald/systemd-resolved logs  
/// - syslog/dnsmasq logs
pub fn extract_dns_fact_impl(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    // Try parsing from journald/syslog using dns_capture module
    if let Some(dns_query) = parse_dns_event(event) {
        let pid = dns_query.pid.unwrap_or(0);

        let proc_key = dns_query
            .proc_key
            .clone()
            .unwrap_or_else(|| format!("proc_{}_{}", host_id, pid));

        let scope_key = build_scope_key(event);

        let fact_type = FactType::DnsResolve {
            proc_key: proc_key.clone(),
            query_name: dns_query.query_name.clone(),
            resolved_ips: dns_query.resolved_ips.clone(),
        };

        let fact_id = Fact::compute_fact_id(host_id, &scope_key, &fact_type, event.ts_ms);

        // Build fields with DNS enrichment
        let mut fields = HashMap::new();
        fields.insert(
            "query_type".to_string(),
            FieldValue::String(format!("{:?}", dns_query.query_type)),
        );

        // Add identity_key for correlation
        if let Some(uid) = event.fields.get("_UID").and_then(|v| v.as_u64()) {
            fields.insert(
                "identity_key".to_string(),
                FieldValue::String(format!("uid:{}", uid)),
            );
        }

        return Some(Fact {
            fact_id,
            ts: event.ts_ms,
            host_id: host_id.to_string(),
            scope_key,
            fact_type,
            fields,
            evidence_ptrs: vec![evidence.clone()],
            conflict_set_id: None,
            visibility_gaps: Vec::new(),
        });
    }

    // Fallback: direct field extraction (eBPF DNS capture)
    let query_name = event
        .fields
        .get("query")
        .or_else(|| event.fields.get("name"))
        .or_else(|| event.fields.get("hostname"))
        .and_then(|v| v.as_str())?
        .to_string();

    let pid = event
        .fields
        .get("pid")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let proc_key = event
        .proc_key
        .clone()
        .unwrap_or_else(|| format!("proc_{}_{}", host_id, pid));

    let scope_key = build_scope_key(event);

    let resolved_ips = event
        .fields
        .get("answers")
        .or_else(|| event.fields.get("resolved"))
        .and_then(|v| {
            v.as_array().map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
        })
        .unwrap_or_default();

    let fact_type = FactType::DnsResolve {
        proc_key: proc_key.clone(),
        query_name: query_name.clone(),
        resolved_ips,
    };

    let fact_id = Fact::compute_fact_id(host_id, &scope_key, &fact_type, event.ts_ms);

    // Build fields
    let mut fields = HashMap::new();

    // Add identity_key for correlation
    if let Some(uid) = event.fields.get("uid").and_then(|v| v.as_u64()) {
        fields.insert(
            "identity_key".to_string(),
            FieldValue::String(format!("uid:{}", uid)),
        );
    }

    Some(Fact {
        fact_id,
        ts: event.ts_ms,
        host_id: host_id.to_string(),
        scope_key,
        fact_type,
        fields,
        evidence_ptrs: vec![evidence.clone()],
        conflict_set_id: None,
        visibility_gaps: Vec::new(),
    })
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Convert millisecond timestamp to DateTime<Utc>
fn timestamp_from_ms(ts_ms: i64) -> DateTime<Utc> {
    Utc.timestamp_millis_opt(ts_ms)
        .single()
        .unwrap_or_else(Utc::now)
}

/// Build scope key from event context
fn build_scope_key(event: &Event) -> String {
    if let Some(proc_key) = &event.proc_key {
        format!("proc:{}", proc_key)
    } else if let Some(identity_key) = &event.identity_key {
        format!("user:{}", identity_key)
    } else {
        format!("host:{}", event.host)
    }
}

/// Check if an executable is a Linux "Living off the Land" binary
pub fn is_linux_lolbin(exe: &str) -> bool {
    let lolbins = [
        // Shells
        "bash",
        "sh",
        "dash",
        "zsh",
        "ksh",
        "csh",
        "tcsh",
        "fish",
        // Interpreters
        "python",
        "python2",
        "python3",
        "perl",
        "ruby",
        "php",
        "lua",
        "node",
        "nodejs",
        // File transfer
        "curl",
        "wget",
        "nc",
        "netcat",
        "ncat",
        "socat",
        "scp",
        "rsync",
        "sftp",
        "ftp",
        // Compilers/build
        "gcc",
        "g++",
        "make",
        "ld",
        "as",
        // System tools that can be abused
        "busybox",
        "at",
        "crontab",
        "systemctl",
        "journalctl",
        "dd",
        "xxd",
        "base64",
        "gzip",
        "tar",
        "zip",
        "unzip",
        // Privilege escalation vectors
        "sudo",
        "su",
        "pkexec",
        "doas",
        // Namespace/container tools
        "nsenter",
        "unshare",
        "chroot",
        "docker",
        "podman",
        "kubectl",
        // Network tools
        "ssh",
        "ssh-keygen",
        "openssl",
        "nmap",
        "tcpdump",
        "iptables",
        // Process manipulation
        "gdb",
        "strace",
        "ltrace",
        "kill",
        "pkill",
        // File manipulation
        "find",
        "xargs",
        "awk",
        "sed",
        "cut",
        "head",
        "tail",
        "tee",
    ];

    // Extract basename
    let basename = exe.rsplit('/').next().unwrap_or(exe);

    lolbins.iter().any(|&lolbin| {
        basename == lolbin
            || basename.starts_with(&format!("{}-", lolbin))
            || basename.starts_with(&format!("{}.", lolbin))
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_event(tags: Vec<&str>, fields: Vec<(&str, serde_json::Value)>) -> Event {
        Event {
            ts_ms: 1704672000000, // 2024-01-08 00:00:00 UTC
            host: "test-host".to_string(),
            tags: tags.into_iter().map(|s| s.to_string()).collect(),
            proc_key: Some("proc_test_1234".to_string()),
            file_key: None,
            identity_key: Some("testuser".to_string()),
            evidence_ptr: Some(edr_core::EvidencePtr {
                stream_id: "linux-ebpf-exec".to_string(),
                segment_id: 1,
                record_index: 100,
            }),
            fields: fields
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        }
    }

    #[test]
    fn test_extract_process_fact() {
        let event = make_test_event(
            vec!["exec", "process"],
            vec![
                ("exe", serde_json::json!("/usr/bin/bash")),
                ("cmdline", serde_json::json!("bash -c 'echo hello'")),
                ("pid", serde_json::json!(1234)),
                ("ppid", serde_json::json!(1000)),
                ("uid", serde_json::json!(1000)),
                ("gid", serde_json::json!(1000)),
                ("cwd", serde_json::json!("/home/user")),
            ],
        );

        let facts = extract_facts(&event);
        assert!(!facts.is_empty(), "Should extract at least one fact");

        let exec_fact = facts
            .iter()
            .find(|f| matches!(&f.fact_type, FactType::Exec { .. }));
        assert!(exec_fact.is_some(), "Should have an Exec fact");

        if let Some(fact) = exec_fact {
            if let FactType::Exec {
                exe_path, cmdline, ..
            } = &fact.fact_type
            {
                assert_eq!(exe_path, "/usr/bin/bash");
                assert_eq!(cmdline.as_deref(), Some("bash -c 'echo hello'"));
            }
        }
    }

    #[test]
    fn test_extract_network_fact() {
        let event = make_test_event(
            vec!["network", "connect"],
            vec![
                ("dest_ip", serde_json::json!("93.184.216.34")),
                ("dest_port", serde_json::json!(443)),
                ("pid", serde_json::json!(5678)),
                ("protocol", serde_json::json!("tcp")),
            ],
        );

        let facts = extract_facts(&event);
        let net_fact = facts
            .iter()
            .find(|f| matches!(&f.fact_type, FactType::OutboundConnect { .. }));
        assert!(net_fact.is_some(), "Should have an OutboundConnect fact");

        if let Some(fact) = net_fact {
            if let FactType::OutboundConnect {
                dst_ip, dst_port, ..
            } = &fact.fact_type
            {
                assert_eq!(dst_ip, "93.184.216.34");
                assert_eq!(*dst_port, 443);
            }
        }
    }

    #[test]
    fn test_extract_auth_fact() {
        let event = make_test_event(
            vec!["auth", "ssh"],
            vec![
                ("user", serde_json::json!("admin")),
                ("source_ip", serde_json::json!("192.168.1.100")),
                ("result", serde_json::json!("success")),
            ],
        );

        let facts = extract_facts(&event);
        let auth_fact = facts
            .iter()
            .find(|f| matches!(&f.fact_type, FactType::AuthEvent { .. }));
        assert!(auth_fact.is_some(), "Should have an AuthEvent fact");

        if let Some(fact) = auth_fact {
            if let FactType::AuthEvent {
                auth_type, success, ..
            } = &fact.fact_type
            {
                assert_eq!(auth_type, "ssh");
                assert!(*success);
            }
        }
    }

    #[test]
    fn test_enrich_tags_from_auditd() {
        let event = make_test_event(
            vec![],
            vec![
                ("syscall", serde_json::json!("execve")),
                ("audit.type", serde_json::json!("SYSCALL")),
            ],
        );

        let tags = enrich_tags_from_linux_source(&event);
        assert!(tags.contains(&"exec".to_string()));
    }

    #[test]
    fn test_is_linux_lolbin() {
        assert!(is_linux_lolbin("/usr/bin/curl"));
        assert!(is_linux_lolbin("/bin/bash"));
        assert!(is_linux_lolbin("python3"));
        assert!(is_linux_lolbin("/usr/local/bin/nc"));
        assert!(!is_linux_lolbin("/opt/myapp/myapp"));
        assert!(!is_linux_lolbin("custom-binary"));
    }
}
