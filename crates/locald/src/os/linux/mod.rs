//! Linux-specific signal detection and fact extraction
//!
//! This module provides:
//! - `fact_extractor`: Converts Linux telemetry to canonical Facts
//! - `signal_engine`: Real-time signal detection engine
//! - `flow_aggregator`: Network flow aggregation for __agg.* fields
//! - `uid_cache`: UID/capability state tracking for before/after
//! - `dns_capture`: DNS query capture and parsing
//!
//! Telemetry sources supported:
//! - auditd (syscall, execve, file access)
//! - eBPF probes (tracepoints, kprobes)
//! - journald/syslog (auth, service events)
//! - procfs snapshots

pub mod dns_capture;
pub mod fact_extractor;
pub mod flow_aggregator;
pub mod signal_engine;
pub mod uid_cache;

pub use dns_capture::{is_dns_event, parse_dns_event, DnsQuery, DnsQueryType};
pub use fact_extractor::{enrich_tags_from_linux_source, extract_facts, is_linux_lolbin};
pub use flow_aggregator::{get_flow_agg, record_network_event, AggFields, FlowAggregator};
pub use signal_engine::LinuxSignalEngine;
pub use uid_cache::{get_process_creds, update_process_creds, CredChange};
