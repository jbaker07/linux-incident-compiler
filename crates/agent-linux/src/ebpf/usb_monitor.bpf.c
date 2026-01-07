// ebpf/usb_monitor.bpf.c
// ON_DEMAND: Monitor USB device operations via block/usb_dev_uevent
// Gated by ondemand_enabled map
// Conditional on tracepoint availability: gracefully skip if not present
// NOTE: edr_events.h already defines the LICENSE symbol; do not redefine here.

#if __has_include("include/edr_events.h")
#  include "include/edr_events.h"
#elif __has_include("../include/edr_events.h")
#  include "../include/edr_events.h"
#else
#  include "edr_events.h"
#endif

/* Verify canonical struct size (384 bytes) */
_Static_assert(sizeof(struct edr_event) == 384, "struct edr_event must be 384 bytes");

#include <bpf/bpf_tracing.h>

#define SAMPLE_RATE 5  // Sample 1 in 5 USB events

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} sample_counter SEC(".maps");

/* usb_dev_uevent: monitor USB device hotplug events
 * Fallback: if tracepoint doesn't exist on this kernel, program simply won't attach
 */
SEC("tracepoint/usb/usb_dev_uevent")
int tp_usb_dev_uevent(struct trace_event_raw_usb_dev_uevent *ctx)
{
    __u32 zero = 0;
    __u8 *enabled = bpf_map_lookup_elem(&ondemand_enabled, &zero);
    if (!enabled || !(*enabled))
        return 0;

    __u64 *counter = bpf_map_lookup_elem(&sample_counter, &zero);
    if (!counter)
        return 0;

    __sync_fetch_and_add(counter, 1);
    if ((*counter) % SAMPLE_RATE != 0)
        return 0;

    struct edr_event ev = {};
    ev.type       = EVT_USB_MONITOR;
    ev.syscall_id = 0;
    ev.tgid       = edr_tgid();
    ev.fd         = -1;

    edr_emit(&ev);
    return 0;
}

/* Fallback: monitor through sysfs writes if tracepoint unavailable
 * This is a secondary hook: write to /sys/kernel/config/usb_gadget/
 * We gate on openat + write to /sys/kernel/config/usb_gadget/*/UDC
 * 
 * Optional: lighter weight alternative if above tracepoint isn't available
 */
SEC("tracepoint/syscalls/sys_enter_open")
int tp_open_usb_sysfs(struct trace_event_raw_sys_enter *ctx)
{
    __u32 zero = 0;
    __u8 *enabled = bpf_map_lookup_elem(&ondemand_enabled, &zero);
    if (!enabled || !(*enabled))
        return 0;

    // Read filename from first argument (char *filename)
    const char *filename = (const char *)ctx->args[0];
    if (!filename)
        return 0;

    // Quick prefix check: is this /sys/kernel/config/usb_gadget/?
    // For safety, read only first 30 bytes
    char buf[40] = {};
    if (bpf_probe_read_user_str(buf, sizeof(buf), filename) < 0)
        return 0;

    // Check for /sys/kernel/config/usb_gadget
    #define USB_SYSFS_PREFIX "/sys/kernel/config/usb_gadget"
    // Simple substring check (verifier-safe)
    for (int i = 0; i < 30; i++) {
        if (buf[i] == 0) break;
        // Look for "usb_gadget" substring
        if (buf[i] == 'u' && buf[i+1] == 's' && buf[i+2] == 'b' && buf[i+3] == '_') {
            struct edr_event ev = {};
            ev.type       = EVT_USB_MONITOR;
            ev.syscall_id = SYS_open;
            ev.tgid       = edr_tgid();
            ev.fd         = -1;

            edr_emit(&ev);
            return 0;
        }
    }

    return 0;
}
