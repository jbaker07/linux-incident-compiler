// ebpf/net_flow.bpf.c
// ON_DEMAND: Network flow tracking via sendto/recvfrom/sendmsg/recvmsg
// Gated by ondemand_enabled map, per-(pid, dst_ip, dst_port) sampling
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

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

/* Per-flow sampling: key = (pid << 32) | flow_hash, value = count
 * Prevents emitting same flow repeatedly
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, __u64);
} flow_samples SEC(".maps");

/* tracepoint/syscalls/sys_enter_sendto(int sockfd, void *buf, size_t len,
 *                                        int flags, struct sockaddr *dest_addr, socklen_t addrlen)
 */
SEC("tracepoint/syscalls/sys_enter_sendto")
int tp_sendto(struct trace_event_raw_sys_enter *ctx)
{
    __u32 zero = 0;
    __u8 *enabled = bpf_map_lookup_elem(&ondemand_enabled, &zero);
    if (!enabled || !(*enabled))
        return 0;

    __u32 pid = edr_tgid() & 0xFFFFFFFF;
    struct sockaddr *dest_addr = (struct sockaddr *)ctx->args[4];
    
    if (!dest_addr)
        return 0;

    // Read destination family
    __u16 fam = 0;
    if (bpf_probe_read_user(&fam, sizeof(__u16), dest_addr) < 0)
        return 0;

    // Sample key based on destination
    __u64 sample_key = 0;
    if (fam == AF_INET) {
        __u16 port;
        __u32 addr;
        if (bpf_probe_read_user(&port, sizeof(__u16), (void *)dest_addr + 2) < 0)
            return 0;
        if (bpf_probe_read_user(&addr, sizeof(__u32), (void *)dest_addr + 4) < 0)
            return 0;
        sample_key = ((__u64)pid << 32) | (port ^ addr);
    } else if (fam == AF_INET6) {
        __u16 port;
        if (bpf_probe_read_user(&port, sizeof(__u16), (void *)dest_addr + 2) < 0)
            return 0;
        __u32 addr_first;
        if (bpf_probe_read_user(&addr_first, sizeof(__u32), (void *)dest_addr + 8) < 0)
            return 0;
        sample_key = ((__u64)pid << 32) | (port ^ addr_first);
    } else {
        return 0;
    }

    // Check if we've already emitted this flow recently
    __u64 *count = bpf_map_lookup_elem(&flow_samples, &sample_key);
    if (count && (*count) > 0) {
        __sync_fetch_and_add(count, 1);
        return 0;
    }

    // Emit event
    struct edr_event ev = {};
    ev.type       = EVT_NET_FLOW;
    ev.syscall_id = SYS_sendto;
    ev.tgid       = edr_tgid();
    ev.fd         = -1;
    ev.flags      = fam;
    ev.aux_u64    = ctx->args[2];  // len

    bpf_map_update_elem(&flow_samples, &sample_key, &sample_key, BPF_ANY);
    edr_emit(&ev);
    return 0;
}

/* Similar for recvfrom: tracepoint/syscalls/sys_enter_recvfrom */
SEC("tracepoint/syscalls/sys_enter_recvfrom")
int tp_recvfrom(struct trace_event_raw_sys_enter *ctx)
{
    __u32 zero = 0;
    __u8 *enabled = bpf_map_lookup_elem(&ondemand_enabled, &zero);
    if (!enabled || !(*enabled))
        return 0;

    __u32 pid = edr_tgid() & 0xFFFFFFFF;
    
    // For recvfrom, we often don't have dest_addr on enter (it's from result)
    // Just log the FD + len for now
    struct edr_event ev = {};
    ev.type       = EVT_NET_FLOW;
    ev.syscall_id = SYS_recvfrom;
    ev.tgid       = edr_tgid();
    ev.fd         = (__s32)ctx->args[0];  // sockfd
    ev.aux_u64    = ctx->args[2];  // len

    edr_emit(&ev);
    return 0;
}
