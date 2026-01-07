// ebpf/encrypted_payload_monitor.bpf.c
// ON_DEMAND: Monitor read/recv syscalls for potential encrypted payloads
// Gated by ondemand_enabled map
// NO entropy computation in BPF (defer to userspace or skip)
// Only tracks: fd, bytes_requested, syscall_id
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

#define SAMPLE_RATE 100  // Only emit 1 in 100 events (very high volume syscalls)

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} sample_counter SEC(".maps");

/* tracepoint/syscalls/sys_enter_read(unsigned int fd, char *buf, size_t count) */
SEC("tracepoint/syscalls/sys_enter_read")
int tp_read(struct trace_event_raw_sys_enter *ctx)
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

    // Emit lightweight event: just fd and bytes_requested
    struct edr_event ev = {};
    ev.type       = EVT_ENCRYPTED_PAYLOAD;
    ev.syscall_id = SYS_read;
    ev.tgid       = edr_tgid();
    ev.fd         = (__s32)ctx->args[0];  // fd
    ev.aux_u64    = ctx->args[2];  // count (bytes requested)

    edr_emit(&ev);
    return 0;
}

/* tracepoint/syscalls/sys_enter_recvfrom(int sockfd, void *buf, size_t len, ...) */
SEC("tracepoint/syscalls/sys_enter_recvfrom")
int tp_recvfrom(struct trace_event_raw_sys_enter *ctx)
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
    ev.type       = EVT_ENCRYPTED_PAYLOAD;
    ev.syscall_id = SYS_recvfrom;
    ev.tgid       = edr_tgid();
    ev.fd         = (__s32)ctx->args[0];  // sockfd
    ev.aux_u64    = ctx->args[2];  // len (bytes requested)

    edr_emit(&ev);
    return 0;
}

/* tracepoint/syscalls/sys_enter_recvmsg(int sockfd, struct msghdr *msg, int flags) */
SEC("tracepoint/syscalls/sys_enter_recvmsg")
int tp_recvmsg(struct trace_event_raw_sys_enter *ctx)
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
    ev.type       = EVT_ENCRYPTED_PAYLOAD;
    ev.syscall_id = SYS_recvmsg;
    ev.tgid       = edr_tgid();
    ev.fd         = (__s32)ctx->args[0];  // sockfd

    edr_emit(&ev);
    return 0;
}
