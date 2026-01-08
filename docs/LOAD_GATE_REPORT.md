# Load Gate Report

## Executive Summary

**Date**: _Fill in after running load test_
**Duration**: 5 minutes sustained load
**Target**: 10,000 events/sec → locald → SQLite
**Result**: _PASS / FAIL_

## Pass/Fail Criteria

| Criterion | Threshold | Actual | Status |
|-----------|-----------|--------|--------|
| Event Loss Rate | < 1% | _TBD_ | ⏳ |
| Queue Drop Rate | < 0.5% | _TBD_ | ⏳ |
| Ingest Lag | < 30s steady-state | _TBD_ | ⏳ |
| DB Commit P95 | < 200ms | _TBD_ | ⏳ |
| Memory Growth | < 50MB over 5min | _TBD_ | ⏳ |
| No Crashes | Zero crashes | _TBD_ | ⏳ |
| No Hangs | All components responsive | _TBD_ | ⏳ |

## Test Procedure

### 1. Start the Stack

```bash
# Terminal 1: Start capture (requires sudo for eBPF)
sudo EDR_TELEMETRY_ROOT=/var/lib/edr ./target/release/capture_linux_rotating

# Terminal 2: Start locald
EDR_TELEMETRY_ROOT=/var/lib/edr ./target/release/edr-locald

# Terminal 3: Start server
EDR_TELEMETRY_ROOT=/var/lib/edr ./target/release/edr-server
```

### 2. Run Load Harness

```bash
# Terminal 4: Generate load for 5 minutes
./scripts/load_harness_linux.sh --duration 300 --rate 10000
```

### 3. Collect Metrics

During and after the test, query the health endpoint:

```bash
# Get current load metrics
curl -s http://localhost:8080/api/health | jq '.load'

# Watch metrics in real-time
watch -n 5 'curl -s http://localhost:8080/api/health | jq ".load"'
```

### 4. Record Memory Usage

```bash
# Before test
ps -o rss,vsz,comm -p $(pgrep -f capture_linux)
ps -o rss,vsz,comm -p $(pgrep -f edr-locald)

# After 5 minutes
ps -o rss,vsz,comm -p $(pgrep -f capture_linux)
ps -o rss,vsz,comm -p $(pgrep -f edr-locald)
```

## Metrics Collection Template

Fill in the following after running the test:

### Capture Metrics

```json
{
  "rb_events_read_total": <VALUE>,
  "rb_events_dropped_total": <VALUE>,
  "capture_queue_depth": <VALUE>,
  "capture_queue_dropped_total": <VALUE>,
  "segment_rotate_total": <VALUE>,
  "segment_write_ms_p95": <VALUE>,
  "index_write_ms_p95": <VALUE>
}
```

**Loss Rate Calculation**:
```
Loss % = (rb_events_dropped_total + capture_queue_dropped_total) / rb_events_read_total * 100
```

### Locald Metrics

```json
{
  "segments_seen_total": <VALUE>,
  "segments_processed_total": <VALUE>,
  "records_processed_total": <VALUE>,
  "fact_extract_ms_p95": <VALUE>,
  "playbook_eval_ms_p95": <VALUE>,
  "ingest_lag_sec": <VALUE>
}
```

**Processing Backlog**:
```
Backlog = segments_seen_total - segments_processed_total
```

### DB Metrics

```json
{
  "db_txn_commit_ms_p95": <VALUE>,
  "db_busy_retries_total": <VALUE>
}
```

### Memory Usage

| Component | Start RSS (KB) | End RSS (KB) | Growth |
|-----------|----------------|--------------|--------|
| capture_linux | _TBD_ | _TBD_ | _TBD_ |
| edr-locald | _TBD_ | _TBD_ | _TBD_ |

## Evidence Collection Commands

### Pre-Test Baseline

```bash
# Save baseline health
curl -s http://localhost:8080/api/health > /tmp/load_gate_baseline.json
date >> /tmp/load_gate_baseline.json

# Save baseline memory
echo "=== MEMORY BASELINE ===" >> /tmp/load_gate_baseline.json
ps aux | grep -E "(capture|locald|edr-server)" | grep -v grep >> /tmp/load_gate_baseline.json
```

### Post-Test Collection

```bash
# Save final health
curl -s http://localhost:8080/api/health > /tmp/load_gate_final.json
date >> /tmp/load_gate_final.json

# Save final memory
echo "=== MEMORY FINAL ===" >> /tmp/load_gate_final.json
ps aux | grep -E "(capture|locald|edr-server)" | grep -v grep >> /tmp/load_gate_final.json

# Generate diff
diff /tmp/load_gate_baseline.json /tmp/load_gate_final.json > /tmp/load_gate_diff.txt || true
```

## Pass/Fail Determination

### PASS Conditions (ALL must be true)

1. **Event Loss < 1%**
   ```
   (rb_events_dropped_total + capture_queue_dropped_total) / rb_events_read_total < 0.01
   ```

2. **No Processing Backlog**
   ```
   segments_seen_total == segments_processed_total (at steady state)
   ```

3. **Acceptable Lag**
   ```
   ingest_lag_sec < 30 (measured 60s after load stops)
   ```

4. **DB Performance**
   ```
   db_txn_commit_ms_p95 < 200
   db_busy_retries_total < 10
   ```

5. **Memory Bounded**
   ```
   RSS growth < 50MB for both capture and locald
   ```

6. **No Crashes/Hangs**
   ```
   All three processes still running after test
   /api/health returns 200 OK with verdict != "blocked"
   ```

### FAIL Conditions (ANY triggers FAIL)

- Event loss > 1%
- segments_seen_total - segments_processed_total > 10 at end
- ingest_lag_sec > 60 at any point
- db_txn_commit_ms_p95 > 500
- Memory growth > 100MB
- Any process crash
- /api/health returns blocked verdict

## Automated Gate Check

Save this as `check_load_gate.sh`:

```bash
#!/bin/bash
# check_load_gate.sh - Automated pass/fail determination

HEALTH=$(curl -s http://localhost:8080/api/health)

# Extract metrics
RB_READ=$(echo "$HEALTH" | jq -r '.load.capture.rb_events_read_total // 0')
RB_DROP=$(echo "$HEALTH" | jq -r '.load.capture.rb_events_dropped_total // 0')
Q_DROP=$(echo "$HEALTH" | jq -r '.load.capture.capture_queue_dropped_total // 0')
SEG_SEEN=$(echo "$HEALTH" | jq -r '.load.locald.segments_seen_total // 0')
SEG_PROC=$(echo "$HEALTH" | jq -r '.load.locald.segments_processed_total // 0')
LAG=$(echo "$HEALTH" | jq -r '.load.locald.ingest_lag_sec // 0')
DB_P95=$(echo "$HEALTH" | jq -r '.load.db.db_txn_commit_ms_p95 // 0')
VERDICT=$(echo "$HEALTH" | jq -r '.verdict')

# Calculate loss rate
if [ "$RB_READ" -gt 0 ]; then
    LOSS_PCT=$(echo "scale=4; ($RB_DROP + $Q_DROP) * 100 / $RB_READ" | bc)
else
    LOSS_PCT="0"
fi

echo "=========================================="
echo " Load Gate Check Results"
echo "=========================================="
echo "Events Read:     $RB_READ"
echo "Events Dropped:  $((RB_DROP + Q_DROP))"
echo "Loss Rate:       ${LOSS_PCT}%"
echo "Seg Backlog:     $((SEG_SEEN - SEG_PROC))"
echo "Ingest Lag:      ${LAG}s"
echo "DB P95:          ${DB_P95}ms"
echo "Verdict:         $VERDICT"
echo ""

# Determine pass/fail
PASS=true
REASONS=""

if (( $(echo "$LOSS_PCT > 1" | bc -l) )); then
    PASS=false
    REASONS="$REASONS\n- Loss rate ${LOSS_PCT}% > 1%"
fi

if [ $((SEG_SEEN - SEG_PROC)) -gt 10 ]; then
    PASS=false
    REASONS="$REASONS\n- Segment backlog > 10"
fi

if (( $(echo "$LAG > 60" | bc -l) )); then
    PASS=false
    REASONS="$REASONS\n- Ingest lag ${LAG}s > 60s"
fi

if (( $(echo "$DB_P95 > 500" | bc -l) )); then
    PASS=false
    REASONS="$REASONS\n- DB P95 ${DB_P95}ms > 500ms"
fi

if [ "$VERDICT" = "blocked" ]; then
    PASS=false
    REASONS="$REASONS\n- Health verdict is blocked"
fi

if [ "$PASS" = true ]; then
    echo "✅ LOAD GATE: PASS"
    exit 0
else
    echo "❌ LOAD GATE: FAIL"
    echo -e "$REASONS"
    exit 1
fi
```

## Sign-Off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Developer | | | |
| QA | | | |
| SRE | | | |

---

## Appendix: Full Health Response Schema

```json
{
  "build": {
    "version": "0.1.0",
    "git_sha": "abc123",
    "build_time": "2025-01-15T10:00:00Z"
  },
  "storage": {
    "telemetry_root": "/var/lib/edr",
    "db_ok": true,
    "disk_free_bytes": 50000000000,
    "writable": true
  },
  "capture": {
    "profile": "standard",
    "throttling_degraded": false,
    "tier0_throttled": false,
    "drops_last_30s": 0,
    "alive": true,
    "pid": 12345
  },
  "streams": [...],
  "imported": {
    "imported_bundles_count": 0,
    "imported_isolated": true
  },
  "load": {
    "capture": {
      "rb_events_read_total": 0,
      "rb_events_dropped_total": 0,
      "capture_queue_depth": 0,
      "capture_queue_dropped_total": 0,
      "segment_rotate_total": 0,
      "segment_write_ms_p95": 0.0,
      "index_write_ms_p95": 0.0
    },
    "locald": {
      "segments_seen_total": 0,
      "segments_processed_total": 0,
      "records_processed_total": 0,
      "fact_extract_ms_p95": 0.0,
      "playbook_eval_ms_p95": 0.0,
      "ingest_lag_sec": 0.0
    },
    "db": {
      "db_txn_commit_ms_p95": 0.0,
      "db_busy_retries_total": 0
    },
    "snapshot_ts": "2025-01-15T10:30:00Z"
  },
  "verdict": "healthy",
  "checked_at": "2025-01-15T10:30:00Z"
}
```
