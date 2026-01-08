//! Load Metrics Collection for Production Readiness
//!
//! Provides unified metrics collection across the capture → locald → DB pipeline.
//! These metrics are exposed via /api/health "load" subsection.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

/// Rolling percentile calculator (approximation using histogram buckets)
pub struct LatencyTracker {
    /// Histogram buckets: <1ms, <5ms, <10ms, <50ms, <100ms, <500ms, <1s, >=1s
    buckets: [AtomicU64; 8],
    /// Max observed value in current window
    max_ms: AtomicU64,
    /// Total samples
    count: AtomicU64,
}

impl Default for LatencyTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl LatencyTracker {
    pub fn new() -> Self {
        Self {
            buckets: Default::default(),
            max_ms: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    pub fn record(&self, ms: u64) {
        self.count.fetch_add(1, Ordering::Relaxed);

        // Update max
        loop {
            let current = self.max_ms.load(Ordering::Relaxed);
            if ms <= current {
                break;
            }
            if self
                .max_ms
                .compare_exchange_weak(current, ms, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }

        // Bucket assignment
        let bucket = match ms {
            0 => 0,
            1..=4 => 1,
            5..=9 => 2,
            10..=49 => 3,
            50..=99 => 4,
            100..=499 => 5,
            500..=999 => 6,
            _ => 7,
        };
        self.buckets[bucket].fetch_add(1, Ordering::Relaxed);
    }

    /// Approximate P95 using histogram
    pub fn p95_approx(&self) -> u64 {
        let total = self.count.load(Ordering::Relaxed);
        if total == 0 {
            return 0;
        }

        let target = (total as f64 * 0.95).ceil() as u64;
        let mut cumulative = 0u64;

        let bucket_maxes = [1, 5, 10, 50, 100, 500, 1000, u64::MAX];
        for (i, &bucket_max) in bucket_maxes.iter().enumerate() {
            cumulative += self.buckets[i].load(Ordering::Relaxed);
            if cumulative >= target {
                return bucket_max.min(self.max_ms.load(Ordering::Relaxed));
            }
        }

        self.max_ms.load(Ordering::Relaxed)
    }

    pub fn max(&self) -> u64 {
        self.max_ms.load(Ordering::Relaxed)
    }

    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    pub fn reset(&self) {
        for bucket in &self.buckets {
            bucket.store(0, Ordering::Relaxed);
        }
        self.max_ms.store(0, Ordering::Relaxed);
        self.count.store(0, Ordering::Relaxed);
    }
}

/// Capture-side metrics (ringbuf + writer)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CaptureLoadMetrics {
    /// Total events read from ringbuf
    pub rb_events_read_total: u64,
    /// Events dropped by kernel (ringbuf overflow)
    pub rb_events_dropped_total: u64,
    /// Current depth of capture queue
    pub capture_queue_depth: u32,
    /// Events dropped due to queue overflow
    pub capture_queue_dropped_total: u64,
    /// Total segment rotations
    pub segment_rotate_total: u64,
    /// P95 segment write latency (ms)
    pub segment_write_ms_p95: u64,
    /// Max segment write latency (ms)
    pub segment_write_ms_max: u64,
    /// P95 index write latency (ms)
    pub index_write_ms_p95: u64,
    /// Max index write latency (ms)
    pub index_write_ms_max: u64,
}

/// Locald-side metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LocaldLoadMetrics {
    /// Total segments seen in index
    pub segments_seen_total: u64,
    /// Total segments fully processed
    pub segments_processed_total: u64,
    /// Total records (events) processed
    pub records_processed_total: u64,
    /// P95 fact extraction latency per batch (ms)
    pub fact_extract_ms_p95: u64,
    /// Max fact extraction latency (ms)
    pub fact_extract_ms_max: u64,
    /// P95 playbook evaluation latency per batch (ms)
    pub playbook_eval_ms_p95: u64,
    /// Max playbook evaluation latency (ms)
    pub playbook_eval_ms_max: u64,
    /// Ingest lag: seconds behind real-time
    pub ingest_lag_sec: f64,
    /// Timestamp of last processed record
    pub last_processed_ts: i64,
}

/// Database metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DbLoadMetrics {
    /// P95 transaction commit latency (ms)
    pub db_txn_commit_ms_p95: u64,
    /// Max transaction commit latency (ms)
    pub db_txn_commit_ms_max: u64,
    /// SQLite busy retries (SQLITE_BUSY)
    pub db_busy_retries_total: u64,
    /// Total transactions committed
    pub db_txn_total: u64,
}

/// Combined load metrics for /api/health
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LoadMetrics {
    pub capture: CaptureLoadMetrics,
    pub locald: LocaldLoadMetrics,
    pub db: DbLoadMetrics,
    /// RSS memory in bytes (capture process)
    pub capture_rss_bytes: u64,
    /// RSS memory in bytes (locald process)
    pub locald_rss_bytes: u64,
    /// Snapshot timestamp
    pub snapshot_ts: i64,
}

/// Thread-safe metrics collector for capture
pub struct CaptureMetricsCollector {
    rb_events_read: AtomicU64,
    rb_events_dropped: AtomicU64,
    queue_depth: AtomicU64,
    queue_dropped: AtomicU64,
    segment_rotations: AtomicU64,
    segment_write_tracker: LatencyTracker,
    index_write_tracker: LatencyTracker,
}

impl Default for CaptureMetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CaptureMetricsCollector {
    pub fn new() -> Self {
        Self {
            rb_events_read: AtomicU64::new(0),
            rb_events_dropped: AtomicU64::new(0),
            queue_depth: AtomicU64::new(0),
            queue_dropped: AtomicU64::new(0),
            segment_rotations: AtomicU64::new(0),
            segment_write_tracker: LatencyTracker::new(),
            index_write_tracker: LatencyTracker::new(),
        }
    }

    pub fn record_rb_read(&self, count: u64) {
        self.rb_events_read.fetch_add(count, Ordering::Relaxed);
    }

    pub fn record_rb_dropped(&self, count: u64) {
        self.rb_events_dropped.fetch_add(count, Ordering::Relaxed);
    }

    pub fn set_queue_depth(&self, depth: u32) {
        self.queue_depth.store(depth as u64, Ordering::Relaxed);
    }

    pub fn record_queue_dropped(&self, count: u64) {
        self.queue_dropped.fetch_add(count, Ordering::Relaxed);
    }

    pub fn record_segment_rotation(&self) {
        self.segment_rotations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_segment_write(&self, ms: u64) {
        self.segment_write_tracker.record(ms);
    }

    pub fn record_index_write(&self, ms: u64) {
        self.index_write_tracker.record(ms);
    }

    pub fn snapshot(&self) -> CaptureLoadMetrics {
        CaptureLoadMetrics {
            rb_events_read_total: self.rb_events_read.load(Ordering::Relaxed),
            rb_events_dropped_total: self.rb_events_dropped.load(Ordering::Relaxed),
            capture_queue_depth: self.queue_depth.load(Ordering::Relaxed) as u32,
            capture_queue_dropped_total: self.queue_dropped.load(Ordering::Relaxed),
            segment_rotate_total: self.segment_rotations.load(Ordering::Relaxed),
            segment_write_ms_p95: self.segment_write_tracker.p95_approx(),
            segment_write_ms_max: self.segment_write_tracker.max(),
            index_write_ms_p95: self.index_write_tracker.p95_approx(),
            index_write_ms_max: self.index_write_tracker.max(),
        }
    }
}

/// Thread-safe metrics collector for locald
pub struct LocaldMetricsCollector {
    segments_seen: AtomicU64,
    segments_processed: AtomicU64,
    records_processed: AtomicU64,
    last_processed_ts: AtomicU64,
    fact_extract_tracker: LatencyTracker,
    playbook_eval_tracker: LatencyTracker,
}

impl Default for LocaldMetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl LocaldMetricsCollector {
    pub fn new() -> Self {
        Self {
            segments_seen: AtomicU64::new(0),
            segments_processed: AtomicU64::new(0),
            records_processed: AtomicU64::new(0),
            last_processed_ts: AtomicU64::new(0),
            fact_extract_tracker: LatencyTracker::new(),
            playbook_eval_tracker: LatencyTracker::new(),
        }
    }

    pub fn record_segment_seen(&self) {
        self.segments_seen.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_segment_processed(&self) {
        self.segments_processed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_records_processed(&self, count: u64) {
        self.records_processed.fetch_add(count, Ordering::Relaxed);
    }

    pub fn set_last_processed_ts(&self, ts: i64) {
        self.last_processed_ts.store(ts as u64, Ordering::Relaxed);
    }

    pub fn record_fact_extract(&self, ms: u64) {
        self.fact_extract_tracker.record(ms);
    }

    pub fn record_playbook_eval(&self, ms: u64) {
        self.playbook_eval_tracker.record(ms);
    }

    pub fn snapshot(&self) -> LocaldLoadMetrics {
        let last_ts = self.last_processed_ts.load(Ordering::Relaxed) as i64;
        let now = chrono::Utc::now().timestamp_millis();
        let lag_sec = if last_ts > 0 {
            ((now - last_ts) as f64 / 1000.0).max(0.0)
        } else {
            0.0
        };

        LocaldLoadMetrics {
            segments_seen_total: self.segments_seen.load(Ordering::Relaxed),
            segments_processed_total: self.segments_processed.load(Ordering::Relaxed),
            records_processed_total: self.records_processed.load(Ordering::Relaxed),
            fact_extract_ms_p95: self.fact_extract_tracker.p95_approx(),
            fact_extract_ms_max: self.fact_extract_tracker.max(),
            playbook_eval_ms_p95: self.playbook_eval_tracker.p95_approx(),
            playbook_eval_ms_max: self.playbook_eval_tracker.max(),
            ingest_lag_sec: lag_sec,
            last_processed_ts: last_ts,
        }
    }
}

/// Thread-safe metrics collector for DB
pub struct DbMetricsCollector {
    txn_total: AtomicU64,
    busy_retries: AtomicU64,
    txn_commit_tracker: LatencyTracker,
}

impl Default for DbMetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl DbMetricsCollector {
    pub fn new() -> Self {
        Self {
            txn_total: AtomicU64::new(0),
            busy_retries: AtomicU64::new(0),
            txn_commit_tracker: LatencyTracker::new(),
        }
    }

    pub fn record_txn_commit(&self, ms: u64) {
        self.txn_total.fetch_add(1, Ordering::Relaxed);
        self.txn_commit_tracker.record(ms);
    }

    pub fn record_busy_retry(&self) {
        self.busy_retries.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> DbLoadMetrics {
        DbLoadMetrics {
            db_txn_commit_ms_p95: self.txn_commit_tracker.p95_approx(),
            db_txn_commit_ms_max: self.txn_commit_tracker.max(),
            db_busy_retries_total: self.busy_retries.load(Ordering::Relaxed),
            db_txn_total: self.txn_total.load(Ordering::Relaxed),
        }
    }
}

/// Get RSS memory for current process (Linux)
#[cfg(target_os = "linux")]
pub fn get_rss_bytes() -> u64 {
    std::fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|s| {
            let parts: Vec<&str> = s.split_whitespace().collect();
            parts.get(1)?.parse::<u64>().ok()
        })
        .map(|pages| pages * 4096) // Assume 4KB pages
        .unwrap_or(0)
}

#[cfg(not(target_os = "linux"))]
pub fn get_rss_bytes() -> u64 {
    0
}

/// Global metrics instance (lazy_static or OnceCell pattern)
use std::sync::OnceLock;

static CAPTURE_METRICS: OnceLock<CaptureMetricsCollector> = OnceLock::new();
static LOCALD_METRICS: OnceLock<LocaldMetricsCollector> = OnceLock::new();
static DB_METRICS: OnceLock<DbMetricsCollector> = OnceLock::new();

pub fn capture_metrics() -> &'static CaptureMetricsCollector {
    CAPTURE_METRICS.get_or_init(CaptureMetricsCollector::new)
}

pub fn locald_metrics() -> &'static LocaldMetricsCollector {
    LOCALD_METRICS.get_or_init(LocaldMetricsCollector::new)
}

pub fn db_metrics() -> &'static DbMetricsCollector {
    DB_METRICS.get_or_init(DbMetricsCollector::new)
}

/// Create combined snapshot for /api/health
pub fn snapshot_all() -> LoadMetrics {
    LoadMetrics {
        capture: capture_metrics().snapshot(),
        locald: locald_metrics().snapshot(),
        db: db_metrics().snapshot(),
        capture_rss_bytes: 0, // Set by capture process
        locald_rss_bytes: get_rss_bytes(),
        snapshot_ts: chrono::Utc::now().timestamp_millis(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_latency_tracker() {
        let tracker = LatencyTracker::new();

        // Add samples
        for i in 0..100 {
            tracker.record(i);
        }

        assert_eq!(tracker.count(), 100);
        assert_eq!(tracker.max(), 99);

        // P95 should be approximately 95
        let p95 = tracker.p95_approx();
        assert!((50..=100).contains(&p95), "P95 was {}", p95);
    }

    #[test]
    fn test_capture_metrics() {
        let collector = CaptureMetricsCollector::new();

        collector.record_rb_read(100);
        collector.record_rb_dropped(5);
        collector.record_segment_rotation();
        collector.record_segment_write(10);

        let snapshot = collector.snapshot();
        assert_eq!(snapshot.rb_events_read_total, 100);
        assert_eq!(snapshot.rb_events_dropped_total, 5);
        assert_eq!(snapshot.segment_rotate_total, 1);
    }

    #[test]
    fn test_locald_metrics_lag() {
        let collector = LocaldMetricsCollector::new();

        // Set a timestamp 5 seconds in the past
        let past_ts = chrono::Utc::now().timestamp_millis() - 5000;
        collector.set_last_processed_ts(past_ts);

        let snapshot = collector.snapshot();
        assert!(
            snapshot.ingest_lag_sec >= 4.9 && snapshot.ingest_lag_sec <= 6.0,
            "Lag was {}",
            snapshot.ingest_lag_sec
        );
    }
}
