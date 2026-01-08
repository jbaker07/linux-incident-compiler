#!/bin/bash
# load_harness_linux.sh - Linux load testing harness for production readiness
#
# Generates high event volume by running file/network/process operations
# in parallel to stress-test the capture → locald → DB pipeline.
#
# Usage:
#   ./scripts/load_harness_linux.sh              # Run 5-minute test
#   ./scripts/load_harness_linux.sh --duration 300  # Custom duration
#   ./scripts/load_harness_linux.sh --rate 10000    # Target events/sec
#   ./scripts/load_harness_linux.sh --dry-run       # Show what would run

set -e

# Configuration
DURATION_SEC=300          # Default: 5 minutes
TARGET_RATE=5000          # Target events per second
WORKERS=4                 # Parallel workers
DRY_RUN=false
TEMP_DIR="/tmp/edr_load_test"
LOG_FILE="$TEMP_DIR/load_harness.log"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --duration)
            DURATION_SEC="$2"
            shift 2
            ;;
        --rate)
            TARGET_RATE="$2"
            shift 2
            ;;
        --workers)
            WORKERS="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --duration SEC    Test duration in seconds (default: 300)"
            echo "  --rate NUM        Target events/sec (default: 5000)"
            echo "  --workers NUM     Parallel workers (default: 4)"
            echo "  --dry-run         Show configuration without running"
            echo ""
            echo "This script generates file, network, and process activity"
            echo "to stress-test the EDR capture pipeline."
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Calculate ops per worker
OPS_PER_WORKER=$((TARGET_RATE / WORKERS))

echo "=========================================="
echo " EDR Load Harness - Linux"
echo "=========================================="
echo "Duration:     ${DURATION_SEC}s"
echo "Target Rate:  ${TARGET_RATE} events/sec"
echo "Workers:      ${WORKERS}"
echo "Ops/Worker:   ${OPS_PER_WORKER} ops/sec"
echo "Temp Dir:     ${TEMP_DIR}"
echo ""

if [ "$DRY_RUN" = true ]; then
    echo "[DRY RUN] Would generate approximately:"
    echo "  - File events: ~$((TARGET_RATE * DURATION_SEC / 3))"
    echo "  - Network events: ~$((TARGET_RATE * DURATION_SEC / 3))"
    echo "  - Process events: ~$((TARGET_RATE * DURATION_SEC / 3))"
    echo ""
    echo "Total: ~$((TARGET_RATE * DURATION_SEC)) events"
    exit 0
fi

# Create temp directory
mkdir -p "$TEMP_DIR"
echo "" > "$LOG_FILE"

# Cleanup function
cleanup() {
    echo ""
    echo "[cleanup] Stopping workers..."
    kill $(jobs -p) 2>/dev/null || true
    rm -rf "$TEMP_DIR" 2>/dev/null || true
    echo "[cleanup] Done"
}
trap cleanup EXIT

# ============================================================================
# File Activity Generator
# Generates: open/write/close events (triggers EVT_OPEN, EVT_WRITE, EVT_CLOSE)
# ============================================================================
file_worker() {
    local id=$1
    local ops_per_sec=$2
    local duration=$3
    local work_dir="$TEMP_DIR/file_worker_$id"
    
    mkdir -p "$work_dir"
    
    local end_time=$((SECONDS + duration))
    local ops=0
    local batch_size=100
    
    while [ $SECONDS -lt $end_time ]; do
        for i in $(seq 1 $batch_size); do
            local fname="$work_dir/test_${ops}_${i}.tmp"
            echo "test data for load testing $(date +%s%N)" > "$fname"
            cat "$fname" > /dev/null
            rm -f "$fname"
            ops=$((ops + 3))  # create, read, delete = 3 ops
        done
        
        # Rate limiting
        local target_ops=$((ops_per_sec * (SECONDS - (end_time - duration) + 1)))
        if [ $ops -gt $target_ops ]; then
            sleep 0.01
        fi
    done
    
    echo "[file_worker_$id] Generated $ops file operations" >> "$LOG_FILE"
}

# ============================================================================
# Network Activity Generator
# Generates: connect/bind events (triggers EVT_CONNECT, EVT_BIND)
# ============================================================================
network_worker() {
    local id=$1
    local ops_per_sec=$2
    local duration=$3
    
    local end_time=$((SECONDS + duration))
    local ops=0
    
    while [ $SECONDS -lt $end_time ]; do
        # HTTP connections to localhost (triggers network events)
        for port in 80 443 8080 8443; do
            (timeout 0.1 bash -c "echo > /dev/tcp/127.0.0.1/$port" 2>/dev/null) || true
            ops=$((ops + 1))
        done
        
        # DNS lookups (triggers network events)
        for _ in {1..5}; do
            host localhost > /dev/null 2>&1 || true
            ops=$((ops + 1))
        done
        
        # Rate limiting
        sleep 0.02
    done
    
    echo "[network_worker_$id] Generated $ops network operations" >> "$LOG_FILE"
}

# ============================================================================
# Process Activity Generator
# Generates: exec/fork/exit events (triggers EVT_EXEC, EVT_CLONE, EVT_EXIT)
# ============================================================================
process_worker() {
    local id=$1
    local ops_per_sec=$2
    local duration=$3
    
    local end_time=$((SECONDS + duration))
    local ops=0
    local batch_size=50
    
    while [ $SECONDS -lt $end_time ]; do
        for _ in $(seq 1 $batch_size); do
            # Quick process spawns (each generates exec+exit events)
            /bin/true
            /bin/echo -n "" > /dev/null
            /usr/bin/id -u > /dev/null 2>&1 || /bin/id -u > /dev/null 2>&1 || true
            ops=$((ops + 6))  # 3 commands * 2 events (exec + exit)
        done
        
        # Rate limiting
        sleep 0.01
    done
    
    echo "[process_worker_$id] Generated $ops process operations" >> "$LOG_FILE"
}

# ============================================================================
# Memory Pressure Generator (for privilege boundary tests)
# ============================================================================
memory_worker() {
    local id=$1
    local duration=$2
    
    local end_time=$((SECONDS + duration))
    
    while [ $SECONDS -lt $end_time ]; do
        # Allocate and free memory to trigger mmap/munmap events
        python3 -c "x = 'A' * (1024*1024); del x" 2>/dev/null || \
        python -c "x = 'A' * (1024*1024); del x" 2>/dev/null || true
        sleep 0.5
    done
    
    echo "[memory_worker_$id] Completed memory pressure cycles" >> "$LOG_FILE"
}

# ============================================================================
# Main Execution
# ============================================================================

echo "[start] Beginning load test at $(date)"
START_TIME=$SECONDS

# Start workers in background
echo "[workers] Starting $WORKERS workers of each type..."

for i in $(seq 1 $WORKERS); do
    file_worker $i $OPS_PER_WORKER $DURATION_SEC &
    network_worker $i $((OPS_PER_WORKER / 10)) $DURATION_SEC &  # Network is slower
    process_worker $i $((OPS_PER_WORKER / 2)) $DURATION_SEC &
done

# Start one memory worker
memory_worker 1 $DURATION_SEC &

# Progress monitoring
echo "[monitor] Workers running, monitoring progress..."
while [ $((SECONDS - START_TIME)) -lt $DURATION_SEC ]; do
    elapsed=$((SECONDS - START_TIME))
    remaining=$((DURATION_SEC - elapsed))
    echo -ne "\r[progress] ${elapsed}s elapsed, ${remaining}s remaining...   "
    sleep 5
done

echo ""
echo "[complete] Load test finished after ${DURATION_SEC}s"

# Wait for workers to finish
wait

# Show summary
echo ""
echo "=========================================="
echo " Load Test Summary"
echo "=========================================="
cat "$LOG_FILE"
echo ""
echo "Check /api/health endpoint for load metrics:"
echo "  curl http://localhost:8080/api/health | jq '.load'"
echo ""
echo "Expected metrics:"
echo "  - rb_events_read_total should be > 0"
echo "  - capture_queue_dropped_total should be < 1% of rb_events_read_total"
echo "  - segments_processed_total should match segments_seen_total"
echo ""
