# Load Metrics Reference

Production observability metrics exposed via `/api/health` under the `load` subsection.

## Overview

The load metrics system provides unified visibility across the capture → locald → DB pipeline.
All counters are monotonic and reset only on process restart.

## Capture Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `rb_events_read_total` | counter | Total events read from eBPF ringbuf/perfbuf |
| `rb_events_dropped_total` | counter | Events dropped by kernel (perfbuf overflow) |
| `capture_queue_depth` | gauge | Current depth of bounded MPSC queue |
| `capture_queue_dropped_total` | counter | Events dropped due to queue full |
| `segment_rotate_total` | counter | Number of segment file rotations |
| `segment_write_ms_p95` | latency | P95 segment write latency (ms) |
| `index_write_ms_p95` | latency | P95 index write latency (ms) |

### Interpretation

- **rb_events_dropped_total > 0**: Kernel-side loss, indicates capture can't keep up with event rate
- **capture_queue_dropped_total > 0**: Application-side backpressure, queue is bounded to prevent OOM
- **segment_write_ms_p95 > 100**: Possible I/O bottleneck, check disk performance

## Locald Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `segments_seen_total` | counter | Segment files detected for processing |
| `segments_processed_total` | counter | Segment files successfully processed |
| `records_processed_total` | counter | Individual records extracted from segments |
| `fact_extract_ms_p95` | latency | P95 fact extraction latency (ms) |
| `playbook_eval_ms_p95` | latency | P95 playbook evaluation latency (ms) |
| `ingest_lag_sec` | gauge | Current lag between segment creation and processing |

### Interpretation

- **segments_seen_total - segments_processed_total > 5**: Processing backlog building up
- **ingest_lag_sec > 60**: Significant lag, locald may be falling behind
- **fact_extract_ms_p95 > 50**: Fact extraction taking longer than expected

## DB Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `db_txn_commit_ms_p95` | latency | P95 transaction commit latency (ms) |
| `db_busy_retries_total` | counter | SQLite BUSY retries (concurrent access contention) |

### Interpretation

- **db_txn_commit_ms_p95 > 100**: Possible disk I/O issue or large transactions
- **db_busy_retries_total increasing**: High contention, consider reducing writer concurrency

## Thresholds for Load Gate

The following thresholds define **PASS** criteria for production load testing:

| Condition | Threshold | Notes |
|-----------|-----------|-------|
| Total loss ratio | < 1% | `(rb_events_dropped_total + capture_queue_dropped_total) / rb_events_read_total` |
| Processing lag | < 30s | `ingest_lag_sec` at steady state |
| DB commit latency | < 200ms P95 | Under sustained load |
| Memory growth | < 50MB | After 5 minutes of sustained 10K events/sec |

## Usage

### Query via /api/health

```bash
curl http://localhost:8080/api/health | jq '.load'
```

### Example Response

```json
{
  "load": {
    "capture": {
      "rb_events_read_total": 1523847,
      "rb_events_dropped_total": 0,
      "capture_queue_depth": 42,
      "capture_queue_dropped_total": 0,
      "segment_rotate_total": 15,
      "segment_write_ms_p95": 12.5,
      "index_write_ms_p95": 2.1
    },
    "locald": {
      "segments_seen_total": 15,
      "segments_processed_total": 14,
      "records_processed_total": 1498234,
      "fact_extract_ms_p95": 8.3,
      "playbook_eval_ms_p95": 15.7,
      "ingest_lag_sec": 3.2
    },
    "db": {
      "db_txn_commit_ms_p95": 45.2,
      "db_busy_retries_total": 0
    },
    "snapshot_ts": "2025-01-15T10:30:00Z"
  }
}
```

## Integration Points

### Capture Process

Call `capture_metrics()` to get the global collector, then:
- `increment_events_read()` after each successful ringbuf poll
- `increment_events_dropped(n)` when perfbuf reports loss
- `set_queue_depth(n)` after queue send
- `increment_queue_dropped()` when queue is full
- `increment_segment_rotate()` on segment close
- `record_segment_write_ms(ms)` with write duration
- `record_index_write_ms(ms)` with index duration

### Locald Process

Call `locald_metrics()` to get the global collector, then:
- `increment_segments_seen()` when detecting new segment
- `increment_segments_processed()` after successful processing
- `increment_records_processed(n)` after parsing records
- `record_fact_extract_ms(ms)` for extraction timing
- `record_playbook_eval_ms(ms)` for playbook timing
- `set_ingest_lag_sec(sec)` with current lag

### DB Layer

Call `db_metrics()` to get the global collector, then:
- `record_txn_commit_ms(ms)` after transaction commit
- `increment_busy_retries()` on SQLITE_BUSY

## Design Notes

1. **Thread-safe**: All collectors use atomics, safe for concurrent access
2. **Zero allocation**: Metric recording doesn't allocate
3. **Approximated percentiles**: Uses histogram buckets for P95, not exact quantiles
4. **Global singletons**: One collector instance per process via `OnceLock`

## See Also

- [SHIP_CHECKLIST.md](../SHIP_CHECKLIST.md) - Production readiness checklist
- [IMPORT_TROUBLESHOOTING.md](IMPORT_TROUBLESHOOTING.md) - Troubleshooting guide
