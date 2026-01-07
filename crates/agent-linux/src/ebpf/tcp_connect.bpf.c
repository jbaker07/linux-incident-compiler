// ebpf/tcp_connect.bpf.c
// kprobe/tcp_v4_connect, kprobe/tcp_v6_connect → edr_event TCP_CONNECT
// Per-(pid, dst_ip, dst_port) sampling to prevent ringbuf floods
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

#include <bpf/bpf_tracing.h>   // BPF_KPROBE

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

/* Sampling map: key = (pid << 32) | hash(dst_ip,dst_port), value = last_seen timestamp
 * Prevents duplicate events for same connection from same PID
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);   // (pid << 32) | flow_hash
    __type(value, __u64); // timestamp
} tcp_connect_samples SEC(".maps");

/* kprobe: tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
 * Called when initiating IPv4 TCP connection
 */
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(k_tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
    if (!sk)
        return 0;

    __u32 pid = edr_tgid() & 0xFFFFFFFF;
    
    // Read destination address from sockaddr_in
    // sockaddr_in: sin_family (2), sin_port (2), sin_addr (4)
    __u16 sin_port;
    __u32 sin_addr;
    if (bpf_probe_read_user(&sin_port, sizeof(__u16), (void *)uaddr + 2) < 0)
        return 0;
    if (bpf_probe_read_user(&sin_addr, sizeof(__u32), (void *)uaddr + 4) < 0)
        return 0;

    // Create sampling key: (pid << 32) | port_addr_hash
    __u32 flow_hash = sin_port ^ sin_addr;
    __u64 sample_key = ((__u64)pid << 32) | flow_hash;

    // Check if we've already sampled this flow recently
    __u64 *last_seen = bpf_map_lookup_elem(&tcp_connect_samples, &sample_key);
    __u64 now = bpf_ktime_get_ns();
    if (last_seen && (now - *last_seen) < 1000000000) // 1 second cooldown
        return 0;

    bpf_map_update_elem(&tcp_connect_samples, &sample_key, &now, BPF_ANY);

    // Emit event
    struct edr_event ev = {};
    ev.type       = EVT_TCP_CONNECT;
    ev.syscall_id = 0;
    ev.tgid       = edr_tgid();
    ev.fd         = -1;
    ev.fam        = AF_INET;
    ev.proto      = IPPROTO_TCP;
    
    // raddr and rport in network byte order
    ev.raddr4     = sin_addr;
    ev.rport      = sin_port;
    
    // laddr and lport from socket
    ev.laddr4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    ev.lport  = BPF_CORE_READ(sk, __sk_common.skc_num);

    edr_emit(&ev);
    return 0;
}

/* kprobe: tcp_v6_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
 * Called when initiating IPv6 TCP connection
 */
SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(k_tcp_v6_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
    if (!sk)
        return 0;

    __u32 pid = edr_tgid() & 0xFFFFFFFF;

    // Read destination address from sockaddr_in6
    // sockaddr_in6: sin6_family (2), sin6_port (2), sin6_flowinfo (4), sin6_addr (16)
    __u16 sin6_port;
    if (bpf_probe_read_user(&sin6_port, sizeof(__u16), (void *)uaddr + 2) < 0)
        return 0;

    struct in6_addr sin6_addr;
    if (bpf_probe_read_user(&sin6_addr, sizeof(sin6_addr), (void *)uaddr + 8) < 0)
        return 0;

    // Sampling key: use first 32 bits of IPv6 + port
    __u32 flow_hash = sin6_port ^ ((__u32 *)&sin6_addr)[0];
    __u64 sample_key = ((__u64)pid << 32) | flow_hash;

    __u64 *last_seen = bpf_map_lookup_elem(&tcp_connect_samples, &sample_key);
    __u64 now = bpf_ktime_get_ns();
    if (last_seen && (now - *last_seen) < 1000000000)
        return 0;

    bpf_map_update_elem(&tcp_connect_samples, &sample_key, &now, BPF_ANY);

    // Emit event
    struct edr_event ev = {};
    ev.type       = EVT_TCP_CONNECT;
    ev.syscall_id = 0;
    ev.tgid       = edr_tgid();
    ev.fd         = -1;
    ev.fam        = AF_INET6;
    ev.proto      = IPPROTO_TCP;
    
    // Remote address and port from userspace
    __builtin_memcpy(ev.raddr6, &sin6_addr, sizeof(ev.raddr6));
    ev.rport      = sin6_port;

    // Local address and port from socket
    struct in6_addr l6 = BPF_CORE_READ(sk, __sk_common.skc_v6_rcv_saddr);
    __builtin_memcpy(ev.laddr6, &l6, sizeof(ev.laddr6));
    ev.lport  = BPF_CORE_READ(sk, __sk_common.skc_num);

    edr_emit(&ev);
    return 0;
}
