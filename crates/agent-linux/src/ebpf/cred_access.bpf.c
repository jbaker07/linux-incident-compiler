// ebpf/cred_access.bpf.c
// ON_DEMAND: Monitor credential/capability access syscalls
// Gated by ondemand_enabled map
// Tracks: capget, capset, getuid, geteuid, getgid, getegid, getgroups
// High sampling rate to avoid floods
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

#define SAMPLE_RATE 10  // Very aggressive sampling: 1 in 10 (these syscalls are high frequency)

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} sample_counter SEC(".maps");

/* tracepoint/syscalls/sys_enter_capget(cap_user_header_t header, cap_user_data_t dataptr) */
SEC("tracepoint/syscalls/sys_enter_capget")
int tp_capget(struct trace_event_raw_sys_enter *ctx)
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
    ev.type       = EVT_CRED_ACCESS;
    ev.syscall_id = SYS_capget;
    ev.tgid       = edr_tgid();
    ev.fd         = -1;

    edr_emit(&ev);
    return 0;
}

/* tracepoint/syscalls/sys_enter_capset(cap_user_header_t header, const cap_user_data_t data) */
SEC("tracepoint/syscalls/sys_enter_capset")
int tp_capset(struct trace_event_raw_sys_enter *ctx)
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
    ev.type       = EVT_CRED_ACCESS;
    ev.syscall_id = SYS_capset;
    ev.tgid       = edr_tgid();
    ev.fd         = -1;

    edr_emit(&ev);
    return 0;
}

/* tracepoint/syscalls/sys_enter_getuid() */
SEC("tracepoint/syscalls/sys_enter_getuid")
int tp_getuid(struct trace_event_raw_sys_enter *ctx)
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
    ev.type       = EVT_CRED_ACCESS;
    ev.syscall_id = SYS_getuid;
    ev.tgid       = edr_tgid();
    ev.fd         = -1;

    edr_emit(&ev);
    return 0;
}

/* tracepoint/syscalls/sys_enter_geteuid() */
SEC("tracepoint/syscalls/sys_enter_geteuid")
int tp_geteuid(struct trace_event_raw_sys_enter *ctx)
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
    ev.type       = EVT_CRED_ACCESS;
    ev.syscall_id = SYS_geteuid;
    ev.tgid       = edr_tgid();
    ev.fd         = -1;

    edr_emit(&ev);
    return 0;
}

/* tracepoint/syscalls/sys_enter_getgid() */
SEC("tracepoint/syscalls/sys_enter_getgid")
int tp_getgid(struct trace_event_raw_sys_enter *ctx)
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
    ev.type       = EVT_CRED_ACCESS;
    ev.syscall_id = SYS_getgid;
    ev.tgid       = edr_tgid();
    ev.fd         = -1;

    edr_emit(&ev);
    return 0;
}

/* tracepoint/syscalls/sys_enter_getegid() */
SEC("tracepoint/syscalls/sys_enter_getegid")
int tp_getegid(struct trace_event_raw_sys_enter *ctx)
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
    ev.type       = EVT_CRED_ACCESS;
    ev.syscall_id = SYS_getegid;
    ev.tgid       = edr_tgid();
    ev.fd         = -1;

    edr_emit(&ev);
    return 0;
}
