

#include "edr_events.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Kernel module loading: init_module/finit_module/delete_module
// ALWAYS_ON, low-volume: all module loads are critical
// Hookpoints: tracepoint/syscalls/sys_enter_{init_module,finit_module,delete_module}
// Filters: None (all are suspicious without context)
// Sampling: None

SEC("tracepoint/syscalls/sys_enter_init_module")
int trace_init_module(struct trace_event_raw_sys_enter *ctx) {
    struct edr_event *e = bpf_ringbuf_reserve(&edr_events_rb, sizeof(*e), 0);
    if (!e) return 0;

    edr_emit(e);
    e->type = EVT_MOD_LOAD;
    e->syscall_id = ctx->id;
    e->aux_u64 = ctx->args[0];  // module_image ptr
    e->aux_u32 = (__u32)ctx->args[1];  // len
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_finit_module")
int trace_finit_module(struct trace_event_raw_sys_enter *ctx) {
    struct edr_event *e = bpf_ringbuf_reserve(&edr_events_rb, sizeof(*e), 0);
    if (!e) return 0;

    edr_emit(e);
    e->type = EVT_MOD_LOAD;
    e->syscall_id = ctx->id;
    e->fd = (__s32)ctx->args[0];  // fd
    e->flags = (__u32)ctx->args[1];  // flags
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_delete_module")
int trace_delete_module(struct trace_event_raw_sys_enter *ctx) {
    const char *name = (const char *)ctx->args[0];
    __u32 flags = (__u32)ctx->args[1];
    
    struct edr_event *e = bpf_ringbuf_reserve(&edr_events_rb, sizeof(*e), 0);
    if (!e) return 0;

    edr_emit(e);
    e->type = EVT_MOD_DEL;
    e->syscall_id = ctx->id;
    e->flags = flags;
    edr_copy_user_str(e->path, name, sizeof(e->path));
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}
