// ebpf/syscall_tracer.bpf.c
// ON_DEMAND: tracepoint/syscalls hooks for high-signal syscalls
// Gated by ondemand_enabled map: prog_id 1 = enabled
// Low sampling: only ~1/10 events emitted (SAMPLE_RATE=10)
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

#define SAMPLE_RATE 10  // Emit 1 in every 10 events

/* Global sampling counter: incremented by each syscall, wrap around at SAMPLE_RATE */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} sample_counter SEC(".maps");

/* High-signal syscalls: exec, fork, memory, privilege, network */
#define TP_ENTER_SYSCALL_ONDEMAND(syscall_name) \
SEC("tracepoint/syscalls/sys_enter_" #syscall_name) \
int tp_enter_##syscall_name(struct trace_event_raw_sys_enter *ctx) { \
    __u32 zero = 0; \
    __u8 *enabled = bpf_map_lookup_elem(&ondemand_enabled, &zero); \
    if (!enabled || !(*enabled)) return 0; \
    \
    __u64 *counter = bpf_map_lookup_elem(&sample_counter, &zero); \
    if (!counter) return 0; \
    \
    __sync_fetch_and_add(counter, 1); \
    if ((*counter) % SAMPLE_RATE != 0) return 0; \
    \
    struct edr_event ev = {}; \
    ev.type       = EVT_SYSCALL_TRACE; \
    ev.syscall_id = (__u32)BPF_CORE_READ(ctx, id); \
    ev.tgid       = edr_tgid(); \
    ev.fd         = -1; \
    edr_emit(&ev); \
    return 0; \
}

// Process exec lineage
TP_ENTER_SYSCALL_ONDEMAND(execve)
TP_ENTER_SYSCALL_ONDEMAND(execveat)

// Process creation
TP_ENTER_SYSCALL_ONDEMAND(fork)
TP_ENTER_SYSCALL_ONDEMAND(vfork)
TP_ENTER_SYSCALL_ONDEMAND(clone)

// Memory & code modification
TP_ENTER_SYSCALL_ONDEMAND(mmap)
TP_ENTER_SYSCALL_ONDEMAND(mprotect)

// Privilege escalation
TP_ENTER_SYSCALL_ONDEMAND(setuid)
TP_ENTER_SYSCALL_ONDEMAND(setreuid)
TP_ENTER_SYSCALL_ONDEMAND(setresuid)
TP_ENTER_SYSCALL_ONDEMAND(capset)

// Network communication
TP_ENTER_SYSCALL_ONDEMAND(connect)

