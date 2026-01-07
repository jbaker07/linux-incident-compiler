// ebpf/container_exec.bpf.c
// ON_DEMAND: Monitor exec syscalls within containers (namespace context)
// Gated by ondemand_enabled map
// Detects exec in container by checking for non-init namespace
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

#define SAMPLE_RATE 20  // Sample 1 in 20 execs in containers

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} sample_counter SEC(".maps");

/* tracepoint/syscalls/sys_enter_execve(const char *filename, const char *const *argv,
 *                                        const char *const *envp)
 */
SEC("tracepoint/syscalls/sys_enter_execve")
int tp_execve(struct trace_event_raw_sys_enter *ctx)
{
    __u32 zero = 0;
    __u8 *enabled = bpf_map_lookup_elem(&ondemand_enabled, &zero);
    if (!enabled || !(*enabled))
        return 0;

    // Check if in container: look for non-init namespace IDs
    struct task_struct *t = (void *)bpf_get_current_task();
    struct nsproxy *ns_proxy = BPF_CORE_READ(t, nsproxy);
    if (!ns_proxy)
        return 0;

    struct pid_namespace *pid_ns = BPF_CORE_READ(ns_proxy, pid_ns_for_children);
    if (!pid_ns)
        return 0;

    // Check if not in init_pid_ns (simplistic: just check if level > 0)
    unsigned int ns_level = BPF_CORE_READ(pid_ns, level);
    if (ns_level == 0)
        return 0;  // Skip init namespace

    // Sample to avoid flood
    __u64 *counter = bpf_map_lookup_elem(&sample_counter, &zero);
    if (!counter)
        return 0;

    __sync_fetch_and_add(counter, 1);
    if ((*counter) % SAMPLE_RATE != 0)
        return 0;

    // Emit event
    struct edr_event ev = {};
    ev.type       = EVT_CONTAINER_EXEC;
    ev.syscall_id = SYS_execve;
    ev.tgid       = edr_tgid();
    ev.fd         = -1;
    ev.aux_u32    = ns_level;  // store namespace level

    edr_emit(&ev);
    return 0;
}

/* tracepoint/syscalls/sys_enter_execveat(int dirfd, const char *pathname,
 *                                          const char *const *argv, const char *const *envp, int flags)
 */
SEC("tracepoint/syscalls/sys_enter_execveat")
int tp_execveat(struct trace_event_raw_sys_enter *ctx)
{
    __u32 zero = 0;
    __u8 *enabled = bpf_map_lookup_elem(&ondemand_enabled, &zero);
    if (!enabled || !(*enabled))
        return 0;

    struct task_struct *t = (void *)bpf_get_current_task();
    struct nsproxy *ns_proxy = BPF_CORE_READ(t, nsproxy);
    if (!ns_proxy)
        return 0;

    struct pid_namespace *pid_ns = BPF_CORE_READ(ns_proxy, pid_ns_for_children);
    if (!pid_ns)
        return 0;

    unsigned int ns_level = BPF_CORE_READ(pid_ns, level);
    if (ns_level == 0)
        return 0;

    __u64 *counter = bpf_map_lookup_elem(&sample_counter, &zero);
    if (!counter)
        return 0;

    __sync_fetch_and_add(counter, 1);
    if ((*counter) % SAMPLE_RATE != 0)
        return 0;

    struct edr_event ev = {};
    ev.type       = EVT_CONTAINER_EXEC;
    ev.syscall_id = SYS_execveat;
    ev.tgid       = edr_tgid();
    ev.fd         = -1;
    ev.aux_u32    = ns_level;

    edr_emit(&ev);
    return 0;
}
