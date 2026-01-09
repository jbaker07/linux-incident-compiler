//! eBPF program framework (Tier-1+ sensors)
//! Legacy eBPF readers moved to attic/rust_deadcode/linux_legacy/ebpf/
//! To be refactored to emit core::Event with no side effects
//!
//! Feature gated behind cfg(target_os="linux") + feature linux_ebpf

pub mod config;
pub mod ebpf_bridge;
pub mod fixtures;
pub mod ingest;
pub mod metrics;
pub mod mock_stream;
pub mod reader;
pub mod ringbuf_reader;
pub mod tests;
pub mod transport;

pub use config::EbpfConfig;
pub use ebpf_bridge::{edr_event_to_core_event, parse_edr_event, EdREvent};
pub use fixtures::{gen_ebpf_events_bin, gen_valid_ebpf_events_bin};
pub use ingest::EbpfIngest;
pub use metrics::{EbpfMetrics, MetricsCollector};
pub use mock_stream::MockEbpfStream;
pub use reader::{
    decode_ebpf_event, get_events_dropped_kernel, get_events_read_total, get_queue_depth,
    get_queue_dropped_total, record_kernel_drop, EbpfReader, ReaderConfig,
};
pub use ringbuf_reader::{RingbufConfig, RingbufReader};
pub use transport::{
    select_ebpf_stream, write_protected_pid, EbpfEventStream, LossMetrics, RawEbpfEvent,
    TransportKind,
};
