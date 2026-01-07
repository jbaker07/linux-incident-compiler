#include "edr_events.h"

/* Verify canonical struct size (384 bytes with ABI fields) */
_Static_assert(sizeof(struct edr_event) == 384, "struct edr_event must be 384 bytes");

/* ===================== proc_lifecycle programs ===================== */

static __always_inline void fill_common(struct edr_event *ev, __u32 type)
{
    /* ABI negotiation fields (MUST be set first) */
    ev->abi_version = 1;
    ev->event_size = 384;
    
    ev->ts         = bpf_ktime_get_ns();
    ev->type       = type;
    ev->syscall_id = 0;
    ev->tgid       = edr_tgid();
    ev->uid        = edr_uid();
    ev->fd         = -1;
    ev->ret        = 0;
    ev->flags      = 0;
    ev->aux_u32    = 0;
    ev->aux_u64    = 0;
    ev->fam        = 0;
    ev->proto      = 0;
    ev->lport      = 0;
    ev->rport      = 0;
    ev->laddr4     = 0;
    ev->raddr4     = 0;
    __builtin_memset(ev->laddr6, 0, sizeof(ev->laddr6));
    __builtin_memset(ev->raddr6, 0, sizeof(ev->raddr6));

    struct task_struct *t = (void *)bpf_get_current_task();
    ev->ppid = BPF_CORE_READ(t, real_parent, tgid);

    __builtin_memset(ev->path, 0, sizeof(ev->path));
    __builtin_memset(ev->path2, 0, sizeof(ev->path2));
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
}

/* sched_process_fork */
SEC("tracepoint/sched/sched_process_fork")
int tp_sched_process_fork(void *ctx)
{
    struct edr_event ev = {};
    fill_common(&ev, EVT_PROC_FORK);
    edr_emit(&ev);
    return 0;
}

/* sched_process_exec */
SEC("tracepoint/sched/sched_process_exec")
int tp_sched_process_exec(void *ctx)
{
    struct edr_event ev = {};
    fill_common(&ev, EVT_PROC_EXEC_TP);

    /* Mirror comm into path for readability */
    __builtin_memcpy(ev.path, ev.comm, sizeof(ev.comm));

    edr_emit(&ev);
    return 0;
}

/* sched_process_exit */
SEC("tracepoint/sched/sched_process_exit")
int tp_sched_process_exit(void *ctx)
{
    struct edr_event ev = {};
    fill_common(&ev, EVT_PROC_EXIT);

    struct task_struct *t = (void *)bpf_get_current_task();
    int exit_code = BPF_CORE_READ(t, exit_code);
    ev.aux_u32 = (__u32)exit_code;

    edr_emit(&ev);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
