

#include "edr_events.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Process injection: ptrace/process_vm_writev/readv/memfd_create
// ALWAYS_ON, low-volume: all injection syscalls are critical; no sampling
// Hookpoints: tracepoint/syscalls/sys_enter_{ptrace,process_vm_writev,process_vm_readv,memfd_create}
// Filters: None (all are suspicious)
// Sampling: None

SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace(struct trace_event_raw_sys_enter *ctx) {
    struct edr_event *e = bpf_ringbuf_reserve(&edr_events_rb, sizeof(*e), 0);
    if (!e) return 0;

    edr_emit(e);
    e->type = EVT_PTRACE;
    e->syscall_id = ctx->id;
    e->aux_u32 = (__u32)ctx->args[1];  // target pid
    e->ret = ctx->args[0];             // request
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_process_vm_writev")
int trace_process_vm_writev(struct trace_event_raw_sys_enter *ctx) {
    struct edr_event *e = bpf_ringbuf_reserve(&edr_events_rb, sizeof(*e), 0);
    if (!e) return 0;

    edr_emit(e);
    e->type = EVT_PTRACE;
    e->syscall_id = ctx->id;
    e->aux_u32 = (__u32)ctx->args[0];  // target pid
    e->flags = 1;                       // Mark as write
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_process_vm_readv")
int trace_process_vm_readv(struct trace_event_raw_sys_enter *ctx) {
    struct edr_event *e = bpf_ringbuf_reserve(&edr_events_rb, sizeof(*e), 0);
    if (!e) return 0;

    edr_emit(e);
    e->type = EVT_PTRACE;
    e->syscall_id = ctx->id;
    e->aux_u32 = (__u32)ctx->args[0];  // target pid
    e->flags = 0;                       // Mark as read
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int trace_memfd_create(struct trace_event_raw_sys_enter *ctx) {
    const char *name = (const char *)ctx->args[0];
    __u32 flags = (__u32)ctx->args[1];
    
    struct edr_event *e = bpf_ringbuf_reserve(&edr_events_rb, sizeof(*e), 0);
    if (!e) return 0;

    edr_emit(e);
    e->type = EVT_MEMFD_CREATE;
    e->syscall_id = ctx->id;
    e->flags = flags;
    edr_copy_user_str(e->path, name, sizeof(e->path));
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}
    struct edr_event *e = reserve_ringbuf_event();
    if (!e) return 0;

    fill_common_event(e, EVENT_PTRACE_INJECTION);
    e->data.ptrace.request = 3; // MEMFD_CREATE marker
    
    __u64 name_ptr = ctx->args[0];
    bpf_probe_read_kernel_str(e->data.ptrace.target_file, 
                              sizeof(e->data.ptrace.target_file),
                              (void *)name_ptr);
    
    submit_event(e);
    return 0;
}
