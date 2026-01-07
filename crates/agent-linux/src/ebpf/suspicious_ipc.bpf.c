// ebpf/suspicious_ipc.bpf.c
// ON_DEMAND: Monitor IPC syscalls (ptrace, process_vm_readv/writev, msgctl, semctl)
// Gated by ondemand_enabled map
// Lightweight: emit only when cross-namespace or suspicious patterns
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

#define SAMPLE_RATE 50  // 1 in 50 for high-volume IPC

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} sample_counter SEC(".maps");

/* tracepoint/syscalls/sys_enter_ptrace(long request, pid_t pid, unsigned long addr, unsigned long data) */
SEC("tracepoint/syscalls/sys_enter_ptrace")
int tp_ptrace(struct trace_event_raw_sys_enter *ctx)
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

    __u32 target_pid = (__u32)ctx->args[1];
    
    struct edr_event ev = {};
    ev.type       = EVT_SUSPICIOUS_IPC;
    ev.syscall_id = SYS_ptrace;
    ev.tgid       = edr_tgid();
    ev.fd         = -1;
    ev.aux_u32    = target_pid;  // target process

    edr_emit(&ev);
    return 0;
}

/* tracepoint/syscalls/sys_enter_process_vm_readv(pid_t pid, const struct iovec *lvec,
 *                                                  unsigned long liovcnt, const struct iovec *rvec,
 *                                                  unsigned long riovcnt, unsigned long flags)
 */
SEC("tracepoint/syscalls/sys_enter_process_vm_readv")
int tp_process_vm_readv(struct trace_event_raw_sys_enter *ctx)
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

    __u32 target_pid = (__u32)ctx->args[0];

    struct edr_event ev = {};
    ev.type       = EVT_SUSPICIOUS_IPC;
    ev.syscall_id = SYS_process_vm_readv;
    ev.tgid       = edr_tgid();
    ev.fd         = -1;
    ev.aux_u32    = target_pid;

    edr_emit(&ev);
    return 0;
}

/* tracepoint/syscalls/sys_enter_process_vm_writev(pid_t pid, const struct iovec *lvec,
 *                                                   unsigned long liovcnt, const struct iovec *rvec,
 *                                                   unsigned long riovcnt, unsigned long flags)
 */
SEC("tracepoint/syscalls/sys_enter_process_vm_writev")
int tp_process_vm_writev(struct trace_event_raw_sys_enter *ctx)
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

    __u32 target_pid = (__u32)ctx->args[0];

    struct edr_event ev = {};
    ev.type       = EVT_SUSPICIOUS_IPC;
    ev.syscall_id = SYS_process_vm_writev;
    ev.tgid       = edr_tgid();
    ev.fd         = -1;
    ev.aux_u32    = target_pid;

    edr_emit(&ev);
    return 0;
}

/* tracepoint/syscalls/sys_enter_msgctl(int msqid, int cmd, struct msqid_ds *buf) */
SEC("tracepoint/syscalls/sys_enter_msgctl")
int tp_msgctl(struct trace_event_raw_sys_enter *ctx)
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
    ev.type       = EVT_SUSPICIOUS_IPC;
    ev.syscall_id = SYS_msgctl;
    ev.tgid       = edr_tgid();
    ev.fd         = -1;

    edr_emit(&ev);
    return 0;
}
