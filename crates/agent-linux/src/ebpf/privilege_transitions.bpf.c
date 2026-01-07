

#include "edr_events.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Privilege transitions: setuid/setgid/setresuid/setresgid/capset
// ALWAYS_ON, low-volume: emit only when uid/gid changes
// Hookpoints: tracepoint/syscalls/sys_enter_setuid, sys_enter_setgid, sys_enter_setresuid, sys_enter_setresgid
// Filters: Skip noop calls (args with -1 = no change)
// Sampling: None

SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_setuid(struct trace_event_raw_sys_enter *ctx) {
    struct edr_event *e = bpf_ringbuf_reserve(&edr_events_rb, sizeof(*e), 0);
    if (!e) return 0;

    __u32 new_uid = (__u32)ctx->args[0];
    __u32 current_uid = edr_uid();
    
    if (new_uid == current_uid) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    edr_emit(e);
    e->type = EVT_SETUID;
    e->syscall_id = ctx->id;
    e->aux_u32 = new_uid;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setgid")
int trace_setgid(struct trace_event_raw_sys_enter *ctx) {
    struct edr_event *e = bpf_ringbuf_reserve(&edr_events_rb, sizeof(*e), 0);
    if (!e) return 0;

    __u32 new_gid = (__u32)ctx->args[0];
    
    edr_emit(e);
    e->type = EVT_SETUID;
    e->syscall_id = ctx->id;
    e->aux_u32 = new_gid;
    e->flags = 1;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setresuid")
int trace_setresuid(struct trace_event_raw_sys_enter *ctx) {
    struct edr_event *e = bpf_ringbuf_reserve(&edr_events_rb, sizeof(*e), 0);
    if (!e) return 0;

    __u32 ruid = (__u32)ctx->args[0];
    __u32 euid = (__u32)ctx->args[1];
    
    if (ruid != (__u32)-1 || euid != (__u32)-1) {
        edr_emit(e);
        e->type = EVT_SETUID;
        e->syscall_id = ctx->id;
        e->aux_u32 = ruid;
        e->ret = euid;
        bpf_ringbuf_submit(e, 0);
    }
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setresgid")
int trace_setresgid(struct trace_event_raw_sys_enter *ctx) {
    struct edr_event *e = bpf_ringbuf_reserve(&edr_events_rb, sizeof(*e), 0);
    if (!e) return 0;

    __u32 rgid = (__u32)ctx->args[0];
    __u32 egid = (__u32)ctx->args[1];
    
    if (rgid != (__u32)-1 || egid != (__u32)-1) {
        edr_emit(e);
        e->type = EVT_SETUID;
        e->syscall_id = ctx->id;
        e->aux_u32 = rgid;
        e->ret = egid;
        e->flags = 1;
        bpf_ringbuf_submit(e, 0);
    }
    
    return 0;
}
