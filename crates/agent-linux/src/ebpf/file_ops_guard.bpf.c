

#include "edr_events.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// File operations guard: openat/unlinkat/renameat2/chmod/chown on sensitive paths
// ALWAYS_ON, low-volume: strict allowlist filtering (/etc/*, /root/*, /sys/kernel/*)
// Hookpoints: tracepoint/syscalls/sys_enter_{openat,unlinkat,renameat2,chmod,chown}
// Filters: Only emit for paths matching allowlist; skip unless open flags indicate write intent
// Sampling: None (allowlist filtering keeps volume low)

static __always_inline bool is_sensitive_path_prefix(const char *path, int max_len) {
    if (!path) return false;
    
    char first_bytes[16] = {};
    bpf_probe_read_user_str(first_bytes, sizeof(first_bytes), path);
    
    // Check for /etc/ or /etc:, /root/, /sys/kernel, /opt/
    if (first_bytes[0] != '/') return false;
    
    if (first_bytes[1] == 'e' && first_bytes[2] == 't' && first_bytes[3] == 'c') return true;
    if (first_bytes[1] == 'r' && first_bytes[2] == 'o' && first_bytes[3] == 'o' && 
        first_bytes[4] == 't') return true;
    if (first_bytes[1] == 's' && first_bytes[2] == 'y' && first_bytes[3] == 's' &&
        first_bytes[4] == '/' && first_bytes[5] == 'k') return true;
    if (first_bytes[1] == 'o' && first_bytes[2] == 'p' && first_bytes[3] == 't') return true;
    
    return false;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    // args[0]=dirfd, args[1]=pathname, args[2]=flags, args[3]=mode
    const char *pathname = (const char *)ctx->args[1];
    __u32 flags = (__u32)ctx->args[2];
    
    // Skip if not on allowlist
    if (!is_sensitive_path_prefix(pathname, 128)) {
        return 0;
    }
    
    // Skip read-only opens (O_WRONLY=1, O_RDWR=2)
    if ((flags & 3) == 0) {  // O_RDONLY
        return 0;
    }

    struct edr_event *e = bpf_ringbuf_reserve(&edr_events_rb, sizeof(*e), 0);
    if (!e) return 0;

    edr_emit(e);
    e->type = EVT_OPEN;
    e->syscall_id = ctx->id;
    e->flags = flags;
    edr_copy_user_str(e->path, pathname, sizeof(e->path));
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_unlinkat(struct trace_event_raw_sys_enter *ctx) {
    // args[0]=dirfd, args[1]=pathname, args[2]=flags
    const char *pathname = (const char *)ctx->args[1];
    
    if (!is_sensitive_path_prefix(pathname, 128)) {
        return 0;
    }

    struct edr_event *e = bpf_ringbuf_reserve(&edr_events_rb, sizeof(*e), 0);
    if (!e) return 0;

    edr_emit(e);
    e->type = EVT_UNLINK;
    e->syscall_id = ctx->id;
    edr_copy_user_str(e->path, pathname, sizeof(e->path));
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int trace_renameat2(struct trace_event_raw_sys_enter *ctx) {
    // args[0]=olddirfd, args[1]=oldpath, args[2]=newdirfd, args[3]=newpath, args[4]=flags
    const char *oldpath = (const char *)ctx->args[1];
    const char *newpath = (const char *)ctx->args[3];
    
    // Emit if either src or dst is sensitive
    if (!is_sensitive_path_prefix(oldpath, 128) && !is_sensitive_path_prefix(newpath, 128)) {
        return 0;
    }

    struct edr_event *e = bpf_ringbuf_reserve(&edr_events_rb, sizeof(*e), 0);
    if (!e) return 0;

    edr_emit(e);
    e->type = EVT_RENAME;
    e->syscall_id = ctx->id;
    edr_copy_user_str(e->path, oldpath, sizeof(e->path));
    edr_copy_user_str(e->path2, newpath, sizeof(e->path2));
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int trace_fchmodat(struct trace_event_raw_sys_enter *ctx) {
    // args[0]=dirfd, args[1]=pathname, args[2]=mode, args[3]=flags
    const char *pathname = (const char *)ctx->args[1];
    __u32 mode = (__u32)ctx->args[2];
    
    if (!is_sensitive_path_prefix(pathname, 128)) {
        return 0;
    }

    struct edr_event *e = bpf_ringbuf_reserve(&edr_events_rb, sizeof(*e), 0);
    if (!e) return 0;

    edr_emit(e);
    e->type = EVT_CHMOD_CHOWN;
    e->syscall_id = ctx->id;
    e->flags = mode;
    edr_copy_user_str(e->path, pathname, sizeof(e->path));
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchownat")
int trace_fchownat(struct trace_event_raw_sys_enter *ctx) {
    // args[0]=dirfd, args[1]=pathname, args[2]=owner, args[3]=group, args[4]=flags
    const char *pathname = (const char *)ctx->args[1];
    __u32 owner = (__u32)ctx->args[2];
    
    if (!is_sensitive_path_prefix(pathname, 128)) {
        return 0;
    }

    struct edr_event *e = bpf_ringbuf_reserve(&edr_events_rb, sizeof(*e), 0);
    if (!e) return 0;

    edr_emit(e);
    e->type = EVT_CHMOD_CHOWN;
    e->syscall_id = ctx->id;
    e->aux_u32 = owner;
    edr_copy_user_str(e->path, pathname, sizeof(e->path));
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}
