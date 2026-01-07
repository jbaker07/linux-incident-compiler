// crates/agent-linux/src/ebpf/ingest.rs
//
// eBPF event ingest - converts raw ringbuf data to edr-core Events.

use crate::ebpf::{edr_event_to_core_event, parse_edr_event};
use edr_core::Event;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Global metrics for eBPF ingest
static EVENTS_IN: AtomicU64 = AtomicU64::new(0);
static EVENTS_ACCEPTED: AtomicU64 = AtomicU64::new(0);
static EVENTS_DROPPED: AtomicU64 = AtomicU64::new(0);

/// Get count of events received from eBPF
pub fn events_in() -> u64 {
    EVENTS_IN.load(Ordering::Relaxed)
}

/// Get count of events accepted
pub fn events_accepted() -> u64 {
    EVENTS_ACCEPTED.load(Ordering::Relaxed)
}

/// Get count of events dropped (parse errors)
pub fn events_dropped() -> u64 {
    EVENTS_DROPPED.load(Ordering::Relaxed)
}

/// eBPF event ingest handler
pub struct EbpfIngest<F>
where
    F: Fn(Event) + Send + Sync,
{
    on_event: Arc<F>,
}

impl<F> EbpfIngest<F>
where
    F: Fn(Event) + Send + Sync + 'static,
{
    pub fn new(on_event: F) -> Self {
        Self {
            on_event: Arc::new(on_event),
        }
    }

    /// Process raw bytes from ringbuf/perf
    pub fn on_raw_event(&self, bytes: &[u8]) -> Option<Event> {
        EVENTS_IN.fetch_add(1, Ordering::Relaxed);

        match parse_edr_event(bytes) {
            Some(raw) => {
                let event = edr_event_to_core_event(&raw);
                EVENTS_ACCEPTED.fetch_add(1, Ordering::Relaxed);
                (self.on_event)(event.clone());
                Some(event)
            }
            None => {
                EVENTS_DROPPED.fetch_add(1, Ordering::Relaxed);
                log::warn!(
                    "failed to parse eBPF event: {} bytes (expected {})",
                    bytes.len(),
                    std::mem::size_of::<crate::ebpf::EdREvent>()
                );
                None
            }
        }
    }

    /// Create a callback closure for ringbuf reader
    pub fn make_callback(&self) -> impl Fn(&[u8]) + Send + Sync + 'static {
        let on_event = self.on_event.clone();
        move |bytes: &[u8]| {
            EVENTS_IN.fetch_add(1, Ordering::Relaxed);
            if let Some(raw) = parse_edr_event(bytes) {
                let event = edr_event_to_core_event(&raw);
                EVENTS_ACCEPTED.fetch_add(1, Ordering::Relaxed);
                on_event(event);
            } else {
                EVENTS_DROPPED.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn test_ingest_callback() {
        let count = Arc::new(AtomicUsize::new(0));
        let count_clone = count.clone();

        let ingest = EbpfIngest::new(move |_event| {
            count_clone.fetch_add(1, Ordering::Relaxed);
        });

        // Create a valid 376-byte EdREvent
        let mut bytes = vec![0u8; 376];
        // Set ts (u64 at offset 0)
        bytes[0..8].copy_from_slice(&1234567890u64.to_ne_bytes());
        // Set type_ (u32 at offset 8) = EVT_EXEC = 30
        bytes[8..12].copy_from_slice(&30u32.to_ne_bytes());

        let result = ingest.on_raw_event(&bytes);
        assert!(result.is_some());
        assert_eq!(count.load(Ordering::Relaxed), 1);
    }
}
