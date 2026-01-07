//! Linux Event Capture Agent
//!
//! Captures security-relevant events from Linux systems using:
//! - eBPF probes (process, file, network)
//! - procfs polling
//! - audit subsystem
//!
//! Writes events to the standard run contract format for consumption
//! by edr-locald and edr-server.

pub mod capture_linux_rotating;
pub mod event_builders;
pub mod host;

#[cfg(target_os = "linux")]
pub mod ebpf;

#[cfg(target_os = "linux")]
pub mod sensors;

#[cfg(target_os = "linux")]
pub mod sensors_v2;
