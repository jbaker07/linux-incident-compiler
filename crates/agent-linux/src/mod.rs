// linux/mod.rs
// Linux sensor module - v2 contract-clean implementations
// Emits core::Event from procfs/eBPF sources
// All Linux-specific deps are feature-gated

pub mod capture_linux_rotating;
pub mod event_builders;
pub mod host;
pub mod sensors; // Contains ebpf_primitives for parity detection
pub mod sensors_v2;

#[cfg(target_os = "linux")]
pub mod ebpf;
