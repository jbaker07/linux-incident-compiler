//! eBPF program framework (Tier-1+ sensors)
//! Legacy eBPF readers moved to attic/rust_deadcode/linux_legacy/ebpf/
//! To be refactored to emit core::Event with no side effects
//!
//! Feature gated behind cfg(target_os="linux") + feature linux_ebpf

pub mod config;
pub mod fixtures;
pub mod metrics;
pub mod mock_stream;
pub mod reader;
pub mod tests;
pub mod transport;

pub use config::EbpfConfig;
pub use fixtures::{gen_ebpf_events_bin, gen_valid_ebpf_events_bin};
pub use metrics::{EbpfMetrics, MetricsCollector};
pub use mock_stream::MockEbpfStream;
pub use reader::{decode_ebpf_event, EbpfReader, ReaderConfig};
pub use transport::{
    select_ebpf_stream, write_protected_pid, EbpfEventStream, LossMetrics, RawEbpfEvent,
    TransportKind,
};
