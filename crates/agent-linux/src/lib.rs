//! Linux Event Capture Agent
//!
//! Captures security-relevant events from Linux systems using:
//! - eBPF probes (process, file, network)
//! - procfs polling
//! - audit subsystem
//!
//! Writes events to the standard run contract format for consumption
//! by edr-locald and edr-server.

// Re-export edr-core as `core` for module compatibility
pub use edr_core as core;

pub mod capture;
pub mod host;

#[cfg(target_os = "linux")]
pub mod ebpf;

// Re-exports
pub use capture::{CaptureConfig, CaptureWriter, SharedCaptureWriter};
pub use host::{HostCtx, HostInfo};
