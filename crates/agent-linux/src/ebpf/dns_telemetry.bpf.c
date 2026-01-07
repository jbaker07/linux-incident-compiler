

#include "edr_events.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// DNS telemetry: sendto/sendmsg on port 53 (UDP) and 853 (DoT)
// ALWAYS_ON, low-volume: only emit for DNS ports
// Hookpoints: tracepoint/syscalls/sys_enter_sendto, sys_enter_sendmsg (filtered by port)
// Filters: Check sockaddr port is 53 or 853; skip if not
// Sampling: None (filtered to DNS ports only)

#define DNS_PORT 53
#define DOT_PORT 853

static __always_inline __u16 get_sockaddr_port(const void *addr) {
    __u16 port = 0;
    if (!addr) return 0;
    bpf_probe_read_user(&port, sizeof(port), (void *)addr + 2);
    return port;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_dns_sendto(struct trace_event_raw_sys_enter *ctx) {
    // args[0]=fd, args[1]=buf, args[2]=len, args[3]=flags,
    // args[4]=dest_addr (sockaddr*), args[5]=addrlen
    
    const void *dest_addr = (const void *)ctx->args[4];
    __u32 len = (__u32)ctx->args[2];
    
    __u16 port = get_sockaddr_port(dest_addr);
    if (port != htons(DNS_PORT) && port != htons(DOT_PORT)) {
        return 0;
    }

    struct edr_event *e = bpf_ringbuf_reserve(&edr_events_rb, sizeof(*e), 0);
    if (!e) return 0;

    edr_emit(e);
    e->type = EVT_SENDTO;
    e->syscall_id = ctx->id;
    e->aux_u32 = len;
    e->rport = port;
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int trace_dns_sendmsg(struct trace_event_raw_sys_enter *ctx) {
    // args[0]=fd, args[1]=msg (struct msghdr*), args[2]=flags
    // msghdr has msg_name (sockaddr*) at offset 0; parse it
    
    const void *msg = (const void *)ctx->args[1];
    if (!msg) return 0;
    
    const void *dest_addr = 0;
    bpf_probe_read_user(&dest_addr, sizeof(dest_addr), msg);
    
    __u16 port = get_sockaddr_port(dest_addr);
    if (port != htons(DNS_PORT) && port != htons(DOT_PORT)) {
        return 0;
    }
    
    struct edr_event *e = bpf_ringbuf_reserve(&edr_events_rb, sizeof(*e), 0);
    if (!e) return 0;

    edr_emit(e);
    e->type = EVT_SENDMSG;
    e->syscall_id = ctx->id;
    e->fd = (__s32)ctx->args[0];
    e->rport = port;
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}
