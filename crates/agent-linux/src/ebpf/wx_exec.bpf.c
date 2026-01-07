// ebpf/wx_exec.bpf.c
// tracepoint/syscalls/sys_enter_mprotect, sys_enter_mmap → edr_event WX_EXEC
// Detects writable memory followed by execute (W→X transitions)
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

#define PROT_READ  0x1
#define PROT_WRITE 0x2
#define PROT_EXEC  0x4

/* Track last time this PID performed a writable mmap/mprotect.
 * If EXEC request comes within 5 seconds, emit WX event.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);   // pid
    __type(value, __u64); // timestamp of last WRITE
} last_write_ts SEC(".maps");

/* tracepoint/syscalls/sys_enter_mmap(unsigned long addr, unsigned long len, 
 *                                      unsigned long prot, ...)
 */
SEC("tracepoint/syscalls/sys_enter_mmap")
int tp_mmap_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 addr = ctx->args[0];
    __u64 len  = ctx->args[1];
    __u64 prot = ctx->args[2];

    __u32 pid = edr_tgid() & 0xFFFFFFFF;

    // If request is for WRITE, record the time
    if (prot & PROT_WRITE) {
        __u64 now = bpf_ktime_get_ns();
        bpf_map_update_elem(&last_write_ts, &pid, &now, BPF_ANY);
    }

    // If request is for EXEC, check if we had WRITE recently
    if (prot & PROT_EXEC) {
        __u64 *last_write = bpf_map_lookup_elem(&last_write_ts, &pid);
        if (last_write) {
            __u64 now = bpf_ktime_get_ns();
            __u64 delta = now - *last_write;
            
            // W→X transition within 5 seconds
            if (delta <= 5000000000ULL) {
                struct edr_event ev = {};
                ev.type       = EVT_WX_EXEC;
                ev.syscall_id = SYS_mmap;  // or SYSCALL_MMAP if available
                ev.tgid       = edr_tgid();
                ev.fd         = -1;
                ev.ret        = 0;
                ev.flags      = (__u16)prot;  // store prot flags
                ev.aux_u32    = (__u32)len;
                ev.aux_u64    = delta / 1000000000ULL;  // seconds since last write
                ev.path[0]    = 0;
                ev.path2[0]   = 0;

                edr_emit(&ev);
            }
        }
    }

    return 0;
}

/* tracepoint/syscalls/sys_enter_mprotect(unsigned long start, size_t len, int prot) */
SEC("tracepoint/syscalls/sys_enter_mprotect")
int tp_mprotect_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 addr = ctx->args[0];
    __u64 len  = ctx->args[1];
    __u64 prot = ctx->args[2];

    __u32 pid = edr_tgid() & 0xFFFFFFFF;

    // If request is for WRITE, record the time
    if (prot & PROT_WRITE) {
        __u64 now = bpf_ktime_get_ns();
        bpf_map_update_elem(&last_write_ts, &pid, &now, BPF_ANY);
    }

    // If request is for EXEC, check if we had WRITE recently
    if (prot & PROT_EXEC) {
        __u64 *last_write = bpf_map_lookup_elem(&last_write_ts, &pid);
        if (last_write) {
            __u64 now = bpf_ktime_get_ns();
            __u64 delta = now - *last_write;
            
            // W→X transition within 5 seconds
            if (delta <= 5000000000ULL) {
                struct edr_event ev = {};
                ev.type       = EVT_WX_EXEC;
                ev.syscall_id = SYS_mprotect;
                ev.tgid       = edr_tgid();
                ev.fd         = -1;
                ev.ret        = 0;
                ev.flags      = (__u16)prot;  // store prot flags
                ev.aux_u32    = (__u32)len;
                ev.aux_u64    = delta / 1000000000ULL;  // seconds since last write
                ev.path[0]    = 0;
                ev.path2[0]   = 0;

                edr_emit(&ev);
            }
        }
    }

    return 0;
}
