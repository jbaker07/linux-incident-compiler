#include "edr_events.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Signal integrity: kill/ptrace/BPF/umount2 on protected processes/mounts
// ALWAYS_ON, low-volume: only emit for critical targets (gated by protected_pids map)
// Hookpoints: tracepoint/syscalls/sys_enter_{kill,ptrace,bpf,umount2}
// Filters: kill/ptrace only to pids in protected_pids map; umount2 only for /sys/*; bpf all
// Sampling: None (inherently low-volume)

static __always_inline bool is_protected_pid(__u32 pid) {
    __u8 *protected = bpf_map_lookup_elem(&protected_pids, &pid);
    return protected && *protected == 1;
}

SEC("tracepoint/syscalls/sys_enter_kill")
int trace_kill(struct trace_event_raw_sys_enter *ctx) {
    __u32 target_pid = (__u32)ctx->args[0];
    __s32 signal = (__s32)ctx->args[1];
    
    if (!is_protected_pid(target_pid) || signal == 0) {
        return 0;
    }

    struct edr_event *e = bpf_ringbuf_reserve(&edr_events_rb, sizeof(*e), 0);
    if (!e) return 0;

    edr_emit(e);
    e->type = EVT_SETUID;
    e->syscall_id = ctx->id;
    e->aux_u32 = target_pid;
    e->ret = signal;
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace(struct trace_event_raw_sys_enter *ctx) {
    __u64 request = ctx->args[0];
    __u32 pid = (__u32)ctx->args[1];
    
    if (request != 16 && request != 17) {
        return 0;
    }
    
    if (!is_protected_pid(pid)) {
        return 0;
    }

    struct edr_event *e = bpf_ringbuf_reserve(&edr_events_rb, sizeof(*e), 0);
    if (!e) return 0;

    edr_emit(e);
    e->type = EVT_PTRACE;
    e->syscall_id = ctx->id;
    e->aux_u32 = pid;
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_umount2")
int trace_umount2(struct trace_event_raw_sys_enter *ctx) {
    const char *path = (const char *)ctx->args[0];
    
    char first_bytes[16] = {};
    bpf_probe_read_user_str(first_bytes, sizeof(first_bytes), path);
    
    // Only emit for /sys/* mounts
    if (first_bytes[0] != '/' || first_bytes[1] != 's') {
        return 0;
    }

    struct edr_event *e = bpf_ringbuf_reserve(&edr_events_rb, sizeof(*e), 0);
    if (!e) return 0;

    edr_emit(e);
    e->type = EVT_UMOUNT2;
    e->syscall_id = ctx->id;
    edr_copy_user_str(e->path, path, sizeof(e->path));
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_bpf")
int trace_bpf(struct trace_event_raw_sys_enter *ctx) {
    __u32 cmd = (__u32)ctx->args[0];
    
    struct edr_event *e = bpf_ringbuf_reserve(&edr_events_rb, sizeof(*e), 0);
    if (!e) return 0;

    edr_emit(e);
    e->type = EVT_BPF;
    e->syscall_id = ctx->id;
    e->aux_u32 = cmd;
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}
