#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <object.bpf.o>" >&2
  exit 1
fi

OBJ="$1"
PINROOT="/sys/fs/bpf/edr"

sudo mkdir -p "$PINROOT"
mount | grep ' type bpf ' >/dev/null || sudo mount -t bpf bpf /sys/fs/bpf
mount | egrep 'tracefs|debugfs' >/dev/null || sudo mount -t tracefs nodev /sys/kernel/tracing || true
[ -f /proc/sys/kernel/perf_event_paranoid ] && echo 1 | sudo tee /proc/sys/kernel/perf_event_paranoid >/dev/null

# discover all program sections in this object
mapfile -t SECS < <(readelf -S "$OBJ" 2>/dev/null \
  | sed -n 's/^ *\[\s*[0-9]\+\]\s\([^ ]\+\).*/\1/p' \
  | egrep '^(tracepoint/|raw_tracepoint/|kprobe/|kretprobe/)')

if [[ ${#SECS[@]} -eq 0 ]]; then
  echo "no attachable sections found in $OBJ" >&2
  exit 2
fi

for SEC in "${SECS[@]}"; do
  # pin path encodes section name; safe for multiple per-object
  PIN="$PINROOT/$(basename "$OBJ").$(echo "$SEC" | tr '/:' '__')"
  echo "==> load: $OBJ :: $SEC -> $PIN"
  sudo bpftool prog load "$OBJ" "$PIN" section "$SEC" pinmaps "$PINROOT/maps" 2>/tmp/edr_bpftool_err.log || {
    echo "LOAD FAILED for $SEC"; tail -n +1 /tmp/edr_bpftool_err.log; dmesg | tail -n 60; exit 1; }

  case "$SEC" in
    tracepoint/*/*)
      CAT=${SEC#tracepoint/}; CAT=${CAT%%/*}
      EVT=${SEC##*/}
      echo "    attach: tracepoint $CAT:$EVT"
      sudo bpftool perf attach pinned "$PIN" tracepoint "$CAT:$EVT"
      ;;
    raw_tracepoint/*)
      EVT=${SEC#raw_tracepoint/}
      echo "    attach: rawtp $EVT"
      sudo bpftool perf attach pinned "$PIN" rawtp "$EVT"
      ;;
    kprobe/*)
      FUNC=${SEC#kprobe/}
      echo "    attach: kprobe $FUNC"
      sudo bpftool perf attach pinned "$PIN" kprobe "$FUNC" || echo "    (warn) kprobe symbol missing? $FUNC"
      ;;
    kretprobe/*)
      FUNC=${SEC#kretprobe/}
      echo "    attach: kretprobe $FUNC"
      sudo bpftool perf attach pinned "$PIN" kretprobe "$FUNC" || echo "    (warn) kretprobe symbol missing? $FUNC"
      ;;
  esac
done

echo "OK: $(basename "$OBJ") attached."
