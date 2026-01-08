//! Decoupled eBPF event reader
//! Hot-path reads ringbuf/perf into bounded MPSC queue
//! Separate thread decodes to core::Event without blocking reader
//!
//! Memory Bound: queue_capacity * sizeof(RawEbpfEvent) ≈ 10000 * 512 = ~5MB
//! Backpressure: Low-priority events dropped first, Critical always kept

use crate::core::Event;
use crate::ebpf::{MetricsCollector, RawEbpfEvent};
use anyhow::Result;
use crossbeam_channel::{bounded, Receiver, Sender, TrySendError};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

/// Global counters for load metrics integration (thread-safe)
static QUEUE_DEPTH: AtomicUsize = AtomicUsize::new(0);
static QUEUE_DROPPED_TOTAL: AtomicU64 = AtomicU64::new(0);
static EVENTS_READ_TOTAL: AtomicU64 = AtomicU64::new(0);
static EVENTS_DROPPED_KERNEL: AtomicU64 = AtomicU64::new(0);

/// Get current queue depth for metrics
pub fn get_queue_depth() -> usize {
    QUEUE_DEPTH.load(Ordering::Relaxed)
}

/// Get total events dropped due to queue full
pub fn get_queue_dropped_total() -> u64 {
    QUEUE_DROPPED_TOTAL.load(Ordering::Relaxed)
}

/// Get total events read from ringbuf/perf
pub fn get_events_read_total() -> u64 {
    EVENTS_READ_TOTAL.load(Ordering::Relaxed)
}

/// Get total events dropped by kernel (perf lost)
pub fn get_events_dropped_kernel() -> u64 {
    EVENTS_DROPPED_KERNEL.load(Ordering::Relaxed)
}

/// Record kernel-side event loss (call from perf callback)
pub fn record_kernel_drop(count: u64) {
    EVENTS_DROPPED_KERNEL.fetch_add(count, Ordering::Relaxed);
}

/// Event priority for backpressure drops
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum EventPriority {
    Low = 1,
    Normal = 2,
    Critical = 3,
}

/// eBPF event with priority info
struct PrioritizedEbpfEvent {
    #[allow(dead_code)]
    raw: RawEbpfEvent,
    priority: EventPriority,
}

impl PrioritizedEbpfEvent {
    fn from_raw(raw: RawEbpfEvent) -> Self {
        let priority = match raw.evt_type {
            // Tier-0: Always keep (critical invariants)
            40 => EventPriority::Critical,  // EVT_MPROTECT (W->X)
            62 => EventPriority::Critical,  // EVT_PTRACE
            80 => EventPriority::Critical,  // EVT_MOD_LOAD
            255 => EventPriority::Critical, // EVT_SENSOR_HEALTH

            // Tier-1: High priority
            30 => EventPriority::Normal,  // EVT_EXEC
            60 => EventPriority::Normal,  // EVT_CLONE
            50 => EventPriority::Normal,  // EVT_SETUID
            51 => EventPriority::Normal,  // EVT_CAPSET
            102 => EventPriority::Normal, // EVT_PROC_FORK
            103 => EventPriority::Normal, // EVT_PROC_EXIT

            // Tier-2+: Low priority (noisy)
            10 | 11 | 12 | 13 | 14 | 15 | 16 | 18 | 19 => EventPriority::Low, // File ops
            20..=28 => EventPriority::Low,                                    // Net ops
            200 | 201 => EventPriority::Low,                                  // TCP state

            _ => EventPriority::Normal,
        };

        Self { raw, priority }
    }
}

/// Configuration for reader
pub struct ReaderConfig {
    /// Maximum events in bounded queue
    pub queue_capacity: usize,
    /// Poll timeout in milliseconds
    pub poll_timeout_ms: i32,
    /// Rate limit for one backpressure event (max per 60s)
    pub backpressure_event_rate_limit: usize,
}

impl Default for ReaderConfig {
    fn default() -> Self {
        Self {
            queue_capacity: 10000,
            poll_timeout_ms: 100,
            backpressure_event_rate_limit: 1, // One backpressure event per cycle
        }
    }
}

/// Hot-path reader thread handle
pub struct EbpfReader {
    #[allow(dead_code)]
    tx: Sender<RawEbpfEvent>,
    rx: Receiver<RawEbpfEvent>,
    metrics: MetricsCollector,
}

impl EbpfReader {
    pub fn new(config: ReaderConfig) -> (Self, thread::JoinHandle<Result<()>>) {
        let (tx, rx) = bounded(config.queue_capacity);
        let tx_clone = tx.clone();
        let _queue_cap = config.queue_capacity;

        let reader_thread = thread::spawn(move || {
            let mut stream = crate::ebpf::select_ebpf_stream(None);
            let mut backpressure_cooldown = 0u32;

            loop {
                match stream.poll(config.poll_timeout_ms) {
                    Ok(events) => {
                        for raw in events {
                            let prio_event = PrioritizedEbpfEvent::from_raw(raw);

                            // Try to send; drop low-priority on backpressure
                            match tx_clone.try_send(raw) {
                                Ok(_) => {
                                    EVENTS_READ_TOTAL.fetch_add(1, Ordering::Relaxed);
                                }
                                Err(TrySendError::Full(_)) => {
                                    // Queue full: drop low-priority, keep critical
                                    if prio_event.priority == EventPriority::Critical {
                                        // Critical: blocking wait (bounded)
                                        if tx_clone.send(raw).is_ok() {
                                            EVENTS_READ_TOTAL.fetch_add(1, Ordering::Relaxed);
                                        }
                                    } else {
                                        // Low/Normal priority: drop and count
                                        QUEUE_DROPPED_TOTAL.fetch_add(1, Ordering::Relaxed);

                                        // Rate-limited backpressure warning
                                        if backpressure_cooldown == 0 {
                                            backpressure_cooldown = 100; // 100 poll cycles = ~10s cooldown
                                        }
                                    }
                                }
                                Err(TrySendError::Disconnected(_)) => {
                                    return Ok(());
                                }
                            }
                        }
                    }
                    Err(_e) => {
                        thread::sleep(Duration::from_millis(100));
                    }
                }

                backpressure_cooldown = backpressure_cooldown.saturating_sub(1);

                // Check if we should exit (crossbeam doesn't have is_closed, check len == 0 after disconnect)
                // For now we rely on Disconnected error
            }
        });

        (
            Self {
                tx: tx.clone(),
                rx,
                metrics: MetricsCollector::new(),
            },
            reader_thread,
        )
    }

    /// Try to receive one event (non-blocking)
    pub fn try_recv(&mut self) -> Option<RawEbpfEvent> {
        self.rx.try_recv().ok()
    }

    /// Receive with timeout
    pub fn recv_timeout(&mut self, timeout: Duration) -> Option<RawEbpfEvent> {
        self.rx.recv_timeout(timeout).ok()
    }

    /// Drain all pending events and update queue depth metric
    pub fn drain(&mut self) -> Vec<RawEbpfEvent> {
        let mut events = Vec::new();
        while let Ok(evt) = self.rx.try_recv() {
            events.push(evt);
        }
        // After drain, queue is empty
        QUEUE_DEPTH.store(0, Ordering::Relaxed);
        events
    }

    /// Drain with depth tracking (returns events and updates global depth)
    pub fn drain_with_depth(&mut self) -> Vec<RawEbpfEvent> {
        let mut events = Vec::new();
        while let Ok(evt) = self.rx.try_recv() {
            events.push(evt);
        }
        let depth = events.len();
        QUEUE_DEPTH.store(depth, Ordering::Relaxed);
        events
    }

    /// Get metrics reference
    pub fn metrics(&mut self) -> &mut MetricsCollector {
        &mut self.metrics
    }
}

/// Decode RawEbpfEvent to core::Event (enrichment happens in capture layer)
pub fn decode_ebpf_event(raw: &RawEbpfEvent) -> Result<Event> {
    let mut fields = std::collections::BTreeMap::new();

    // Process info
    fields.insert(
        "process_id".to_string(),
        serde_json::Value::Number(raw.tgid.into()),
    );
    fields.insert(
        "parent_process_id".to_string(),
        serde_json::Value::Number(raw.ppid.into()),
    );
    fields.insert(
        "user_id".to_string(),
        serde_json::Value::Number(raw.uid.into()),
    );

    if raw.fd >= 0 {
        fields.insert(
            "file_descriptor".to_string(),
            serde_json::Value::Number(raw.fd.into()),
        );
    }

    if raw.ret != 0 {
        fields.insert(
            "syscall_return".to_string(),
            serde_json::Value::Number(raw.ret.into()),
        );
    }

    // Networking fields
    if raw.fam != 0 {
        fields.insert(
            "address_family".to_string(),
            serde_json::Value::Number(raw.fam.into()),
        );
    }

    if raw.lport > 0 {
        fields.insert(
            "local_port".to_string(),
            serde_json::Value::Number((u16::from_be(raw.lport) as u32).into()),
        );
    }

    if raw.rport > 0 {
        fields.insert(
            "remote_port".to_string(),
            serde_json::Value::Number((u16::from_be(raw.rport) as u32).into()),
        );
    }

    // Build tags
    let mut tags = vec![format!("evt_type_{}", raw.evt_type)];

    // Paths (truncated)
    let path_str = String::from_utf8_lossy(&raw.path[..])
        .trim_end_matches('\0')
        .to_string();
    if !path_str.is_empty() {
        tags.push(format!("path_{}", path_str.replace('/', "_")));
        fields.insert("path".to_string(), serde_json::Value::String(path_str));
    }

    let path2_str = String::from_utf8_lossy(&raw.path2[..])
        .trim_end_matches('\0')
        .to_string();
    if !path2_str.is_empty() {
        fields.insert("path2".to_string(), serde_json::Value::String(path2_str));
    }

    // Comm
    let comm_str = String::from_utf8_lossy(&raw.comm[..])
        .trim_end_matches('\0')
        .to_string();
    if !comm_str.is_empty() {
        tags.push(format!("comm_{}", comm_str));
    }

    // Construct Event
    let event = Event {
        ts_ms: (raw.ts / 1_000_000) as i64,
        host: String::new(), // Filled by capture layer
        tags,
        proc_key: None,
        file_key: None,
        identity_key: None,
        evidence_ptr: None,
        fields,
    };

    Ok(event)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn test_event_priority_ordering() {
        let mut raw = RawEbpfEvent::default();
        raw.evt_type = 40; // EVT_MPROTECT
        let prio = PrioritizedEbpfEvent::from_raw(raw);
        assert_eq!(prio.priority, EventPriority::Critical);

        let mut raw2 = RawEbpfEvent::default();
        raw2.evt_type = 10; // EVT_OPEN
        let prio2 = PrioritizedEbpfEvent::from_raw(raw2);
        assert_eq!(prio2.priority, EventPriority::Low);
    }
}
