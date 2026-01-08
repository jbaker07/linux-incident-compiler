#!/bin/bash
# check_load_gate.sh - Automated pass/fail determination for load gate
#
# Usage:
#   ./scripts/check_load_gate.sh              # Check against localhost:8080
#   ./scripts/check_load_gate.sh --url URL    # Check against custom URL
#   ./scripts/check_load_gate.sh --output FILE # Save report to file

set -e

# Configuration
API_URL="http://localhost:8080/api/health"
OUTPUT_FILE=""
VERBOSE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --url)
            API_URL="$2"
            shift 2
            ;;
        --output|-o)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --url URL        Health endpoint URL (default: http://localhost:8080/api/health)"
            echo "  --output FILE    Save report to file"
            echo "  --verbose        Show detailed output"
            echo ""
            echo "Exit codes:"
            echo "  0 = PASS"
            echo "  1 = FAIL"
            echo "  2 = ERROR (could not reach endpoint)"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 2
            ;;
    esac
done

# Fetch health data
echo "Fetching health data from $API_URL..."
HEALTH=$(curl -s -f "$API_URL" 2>/dev/null) || {
    echo "ERROR: Could not reach health endpoint at $API_URL"
    exit 2
}

# Extract metrics with defaults
extract() {
    echo "$HEALTH" | jq -r "$1 // $2"
}

# Capture metrics
RB_READ=$(extract '.load.capture.rb_events_read_total' '0')
RB_DROP=$(extract '.load.capture.rb_events_dropped_total' '0')
Q_DROP=$(extract '.load.capture.capture_queue_dropped_total' '0')
Q_DEPTH=$(extract '.load.capture.capture_queue_depth' '0')
SEG_ROTATE=$(extract '.load.capture.segment_rotate_total' '0')
SEG_WRITE_P95=$(extract '.load.capture.segment_write_ms_p95' '0')
INDEX_WRITE_P95=$(extract '.load.capture.index_write_ms_p95' '0')

# Locald metrics
SEG_SEEN=$(extract '.load.locald.segments_seen_total' '0')
SEG_PROC=$(extract '.load.locald.segments_processed_total' '0')
REC_PROC=$(extract '.load.locald.records_processed_total' '0')
FACT_P95=$(extract '.load.locald.fact_extract_ms_p95' '0')
PLAYBOOK_P95=$(extract '.load.locald.playbook_eval_ms_p95' '0')
LAG=$(extract '.load.locald.ingest_lag_sec' '0')

# DB metrics
DB_COMMIT_P95=$(extract '.load.db.db_txn_commit_ms_p95' '0')
DB_BUSY=$(extract '.load.db.db_busy_retries_total' '0')

# Overall verdict
VERDICT=$(extract '.verdict' '"unknown"')
CAPTURE_ALIVE=$(extract '.capture.alive' 'false')

# Calculate loss rate
if [ "$RB_READ" -gt 0 ]; then
    TOTAL_DROP=$((RB_DROP + Q_DROP))
    LOSS_PCT=$(echo "scale=4; $TOTAL_DROP * 100 / $RB_READ" | bc)
else
    TOTAL_DROP=0
    LOSS_PCT="0"
fi

# Calculate segment backlog
SEG_BACKLOG=$((SEG_SEEN - SEG_PROC))

# Output formatting
output() {
    echo "$1"
    if [ -n "$OUTPUT_FILE" ]; then
        echo "$1" >> "$OUTPUT_FILE"
    fi
}

# Clear output file if specified
if [ -n "$OUTPUT_FILE" ]; then
    > "$OUTPUT_FILE"
fi

output "=========================================="
output " EDR Load Gate Check"
output " $(date -Iseconds)"
output "=========================================="
output ""
output "CAPTURE METRICS"
output "  Events Read:       $RB_READ"
output "  Kernel Drops:      $RB_DROP"
output "  Queue Drops:       $Q_DROP"
output "  Queue Depth:       $Q_DEPTH"
output "  Total Loss:        $TOTAL_DROP (${LOSS_PCT}%)"
output "  Segment Rotations: $SEG_ROTATE"
output "  Segment Write P95: ${SEG_WRITE_P95}ms"
output "  Index Write P95:   ${INDEX_WRITE_P95}ms"
output "  Capture Alive:     $CAPTURE_ALIVE"
output ""
output "LOCALD METRICS"
output "  Segments Seen:     $SEG_SEEN"
output "  Segments Processed:$SEG_PROC"
output "  Segment Backlog:   $SEG_BACKLOG"
output "  Records Processed: $REC_PROC"
output "  Fact Extract P95:  ${FACT_P95}ms"
output "  Playbook Eval P95: ${PLAYBOOK_P95}ms"
output "  Ingest Lag:        ${LAG}s"
output ""
output "DB METRICS"
output "  Commit P95:        ${DB_COMMIT_P95}ms"
output "  Busy Retries:      $DB_BUSY"
output ""
output "OVERALL"
output "  Health Verdict:    $VERDICT"
output ""

# ============================================================================
# Pass/Fail Determination
# ============================================================================

PASS=true
REASONS=""

# Check 1: Loss rate < 1%
if (( $(echo "$LOSS_PCT > 1" | bc -l) )); then
    PASS=false
    REASONS="$REASONS\n  ❌ Loss rate ${LOSS_PCT}% > 1% threshold"
else
    output "  ✅ Loss rate ${LOSS_PCT}% < 1%"
fi

# Check 2: Segment backlog < 10
if [ "$SEG_BACKLOG" -gt 10 ]; then
    PASS=false
    REASONS="$REASONS\n  ❌ Segment backlog $SEG_BACKLOG > 10"
else
    output "  ✅ Segment backlog $SEG_BACKLOG <= 10"
fi

# Check 3: Ingest lag < 60s
if (( $(echo "$LAG > 60" | bc -l) )); then
    PASS=false
    REASONS="$REASONS\n  ❌ Ingest lag ${LAG}s > 60s threshold"
else
    output "  ✅ Ingest lag ${LAG}s < 60s"
fi

# Check 4: DB commit P95 < 500ms
if (( $(echo "$DB_COMMIT_P95 > 500" | bc -l) )); then
    PASS=false
    REASONS="$REASONS\n  ❌ DB commit P95 ${DB_COMMIT_P95}ms > 500ms threshold"
else
    output "  ✅ DB commit P95 ${DB_COMMIT_P95}ms < 500ms"
fi

# Check 5: Health verdict not blocked
if [ "$VERDICT" = "blocked" ]; then
    PASS=false
    REASONS="$REASONS\n  ❌ Health verdict is 'blocked'"
else
    output "  ✅ Health verdict is '$VERDICT'"
fi

# Check 6: Capture process alive
if [ "$CAPTURE_ALIVE" != "true" ]; then
    PASS=false
    REASONS="$REASONS\n  ❌ Capture process not alive"
else
    output "  ✅ Capture process alive"
fi

output ""
output "=========================================="

if [ "$PASS" = true ]; then
    output "  ✅ LOAD GATE: PASS"
    output "=========================================="
    exit 0
else
    output "  ❌ LOAD GATE: FAIL"
    output ""
    output "FAILURE REASONS:"
    output -e "$REASONS"
    output "=========================================="
    exit 1
fi
