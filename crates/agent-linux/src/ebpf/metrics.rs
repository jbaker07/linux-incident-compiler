//! eBPF loss metrics collection and reporting
//! Tracks reserve failures, perf lost samples, decode errors, and backpressure drops

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Snapshot of eBPF system metrics at a point in time
#[derive(Debug, Clone)]
pub struct EbpfMetrics {
    pub timestamp_ms: u64,

    // Ringbuf reserve failures
    pub ringbuf_reserve_failed_total: u64,
    pub ringbuf_reserve_failed_delta_5s: u64,

    // Perf lost samples
    pub perf_lost_total: u64,
    pub perf_lost_delta_5s: u64,

    // Events read
    pub events_read_total: u64,
    pub events_read_delta_5s: u64,

    // Decode errors
    pub decode_failed_total: u64,
    pub decode_failed_delta_5s: u64,

    // Userspace backpressure
    pub queue_dropped_total: u64,
    pub queue_dropped_delta_5s: u64,

    // Queue state
    pub queue_len: u32,
    pub queue_cap: u32,

    // Transport
    pub transport: String, // "ringbuf" | "perf" | "none"
}

impl Default for EbpfMetrics {
    fn default() -> Self {
        Self {
            timestamp_ms: 0,
            ringbuf_reserve_failed_total: 0,
            ringbuf_reserve_failed_delta_5s: 0,
            perf_lost_total: 0,
            perf_lost_delta_5s: 0,
            events_read_total: 0,
            events_read_delta_5s: 0,
            decode_failed_total: 0,
            decode_failed_delta_5s: 0,
            queue_dropped_total: 0,
            queue_dropped_delta_5s: 0,
            queue_len: 0,
            queue_cap: 0,
            transport: "none".to_string(),
        }
    }
}

/// Circular buffer for 5-second history (10 samples @ 500ms each)
struct RollingWindow {
    samples: [u64; 10],
    index: usize,
}

impl RollingWindow {
    fn new() -> Self {
        Self {
            samples: [0; 10],
            index: 0,
        }
    }

    fn push(&mut self, value: u64) {
        self.samples[self.index] = value;
        self.index = (self.index + 1) % 10;
    }

    fn delta(&self) -> u64 {
        self.samples.iter().sum()
    }
}

/// Metrics collector with rolling windows
pub struct MetricsCollector {
    // Current totals
    reserve_failed_total: u64,
    perf_lost_total: u64,
    events_read_total: u64,
    decode_failed_total: u64,
    queue_dropped_total: u64,

    // Rolling windows for 5s deltas
    reserve_failed_window: RollingWindow,
    perf_lost_window: RollingWindow,
    events_read_window: RollingWindow,
    decode_failed_window: RollingWindow,
    queue_dropped_window: RollingWindow,

    // Last recorded values for delta calculation
    last_reserve_failed: u64,
    last_perf_lost: u64,
    last_events_read: u64,
    last_decode_failed: u64,
    last_queue_dropped: u64,

    // Queue state
    queue_len: u32,
    queue_cap: u32,

    // Transport
    transport: String,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            reserve_failed_total: 0,
            perf_lost_total: 0,
            events_read_total: 0,
            decode_failed_total: 0,
            queue_dropped_total: 0,
            reserve_failed_window: RollingWindow::new(),
            perf_lost_window: RollingWindow::new(),
            events_read_window: RollingWindow::new(),
            decode_failed_window: RollingWindow::new(),
            queue_dropped_window: RollingWindow::new(),
            last_reserve_failed: 0,
            last_perf_lost: 0,
            last_events_read: 0,
            last_decode_failed: 0,
            last_queue_dropped: 0,
            queue_len: 0,
            queue_cap: 0,
            transport: "none".to_string(),
        }
    }

    pub fn set_transport(&mut self, kind: &str) {
        self.transport = kind.to_string();
    }

    pub fn record_reserve_failed(&mut self, count: u64) {
        self.reserve_failed_total += count;
    }

    pub fn record_perf_lost(&mut self, count: u64) {
        self.perf_lost_total += count;
    }

    pub fn record_events_read(&mut self, count: u64) {
        self.events_read_total += count;
    }

    pub fn record_decode_failed(&mut self, count: u64) {
        self.decode_failed_total += count;
    }

    pub fn record_queue_dropped(&mut self, count: u64) {
        self.queue_dropped_total += count;
    }

    pub fn set_queue_state(&mut self, len: u32, cap: u32) {
        self.queue_len = len;
        self.queue_cap = cap;
    }

    pub fn sample(&mut self) -> EbpfMetrics {
        // Calculate deltas since last sample
        let reserve_failed_delta = self.reserve_failed_total - self.last_reserve_failed;
        let perf_lost_delta = self.perf_lost_total - self.last_perf_lost;
        let events_read_delta = self.events_read_total - self.last_events_read;
        let decode_failed_delta = self.decode_failed_total - self.last_decode_failed;
        let queue_dropped_delta = self.queue_dropped_total - self.last_queue_dropped;

        // Update rolling windows
        self.reserve_failed_window.push(reserve_failed_delta);
        self.perf_lost_window.push(perf_lost_delta);
        self.events_read_window.push(events_read_delta);
        self.decode_failed_window.push(decode_failed_delta);
        self.queue_dropped_window.push(queue_dropped_delta);

        // Update last recorded values
        self.last_reserve_failed = self.reserve_failed_total;
        self.last_perf_lost = self.perf_lost_total;
        self.last_events_read = self.events_read_total;
        self.last_decode_failed = self.decode_failed_total;
        self.last_queue_dropped = self.queue_dropped_total;

        EbpfMetrics {
            timestamp_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            ringbuf_reserve_failed_total: self.reserve_failed_total,
            ringbuf_reserve_failed_delta_5s: self.reserve_failed_window.delta(),
            perf_lost_total: self.perf_lost_total,
            perf_lost_delta_5s: self.perf_lost_window.delta(),
            events_read_total: self.events_read_total,
            events_read_delta_5s: self.events_read_window.delta(),
            decode_failed_total: self.decode_failed_total,
            decode_failed_delta_5s: self.decode_failed_window.delta(),
            queue_dropped_total: self.queue_dropped_total,
            queue_dropped_delta_5s: self.queue_dropped_window.delta(),
            queue_len: self.queue_len,
            queue_cap: self.queue_cap,
            transport: self.transport.clone(),
        }
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}
