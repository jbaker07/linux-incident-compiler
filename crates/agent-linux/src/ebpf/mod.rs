// crates/agent-linux/src/ebpf/mod.rs
//
// Linux eBPF subsystem for kernel telemetry collection.

pub mod ebpf_bridge;
pub mod ringbuf_reader;
pub mod ingest;

pub use ebpf_bridge::{edr_event_to_core_event, parse_edr_event, EdREvent};
pub use ringbuf_reader::RingbufReader;
pub use ingest::EbpfIngest;
