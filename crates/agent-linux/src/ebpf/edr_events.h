// ebpf/include/edr_events.h
#ifndef __EDR_EVENTS_H
#define __EDR_EVENTS_H

#include "include/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* AF_* fallbacks to avoid pulling UAPI linux headers */
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* -------- Event types (stable ids) -------- */
enum edr_evt_type {
    /* process/memory */
    EVT_EXEC            = 30,
    EVT_CLONE           = 60,
    EVT_MPROTECT        = 40,
    EVT_MEMFD_CREATE    = 42,
    EVT_PTRACE          = 62,
    EVT_PRCTL           = 63,
    EVT_SECCOMP         = 64,
    EVT_PROC_EXEC_TP    = 101,
    EVT_PROC_FORK       = 102,
    EVT_PROC_EXIT       = 103,

    /* --- tcp state & retrans ---*/
    EVT_TCP_STATE       = 200,
    EVT_TCP_RETRANS     = 201,
    
    /* file fs */
    EVT_OPEN            = 10,   // openat/openat2 (exit carries ret fd)
    EVT_RENAME          = 11,   // renameat2
    EVT_UNLINK          = 14,   // unlinkat
    EVT_CHMOD_CHOWN     = 15,   // chmod/chown
    EVT_SETXATTR        = 16,   // setxattr family
    EVT_CLOSE           = 18,   // close
    EVT_DUP             = 19,   // dup/dup2/dup3

    /* networking */
    EVT_SOCKET          = 20,   // exit carries ret fd
    EVT_BIND            = 22,
    EVT_LISTEN          = 23,
    EVT_CONNECT         = 21,
    EVT_ACCEPT          = 24,   // accept/accept4 (exit carries new fd + peer)
    EVT_SENDTO          = 25,
    EVT_SENDMSG         = 26,
    EVT_RECVFROM        = 27,
    EVT_RECVMSG         = 28,
    EVT_READ            = 12,
    EVT_WRITE           = 13,

    /* namespaces/mount/modules/bpf */
    EVT_SETNS           = 70,
    EVT_UNSHARE         = 71,
    EVT_MOUNT           = 72,
    EVT_UMOUNT2         = 73,
    EVT_PIVOT_ROOT      = 74,
    EVT_MOD_LOAD        = 80,   // init_module/finit_module
    EVT_MOD_DEL         = 81,   // delete_module
    EVT_BPF             = 90,

    /* privilege */
    EVT_SETUID          = 50,
    EVT_CAPSET          = 51,

    /* sensor meta */
    EVT_SENSOR_HEALTH   = 255,  // heartbeat event (reserve_failed, lost_samples, etc.)
};

/* -------- ringbuf -------- */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} edr_events_rb SEC(".maps");

/* -------- counter for ringbuf_reserve failures (per-cpu) -------- */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} edr_rb_reserve_failed SEC(".maps");

/* -------- counter for events successfully reserved -------- */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} edr_events_reserved SEC(".maps");

/* -------- per-pid sampling counters (LRU) -------- */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);  // pid (key)
    __type(value, __u64); // sample counter
} edr_sample_counters SEC(".maps");

/* -------- allow list by syscall id (optional; set from userspace) -------- */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);  // syscall id
    __type(value, __u8); // 1=enabled
} edr_allow_syscalls SEC(".maps");

/* -------- protected PIDs for signal integrity (pinned, userspace-populated) -------- */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, __u32);  // pid (e.g., capture, init, systemd)
    __type(value, __u8); // 1=protected
} protected_pids SEC(".maps");

/* -------- ON_DEMAND program enable gates (pinned, userspace-set) -------- */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u32);  // program id (enum)
    __type(value, __u8); // 1=enabled
} ondemand_enabled SEC(".maps");

/* -------- per-proc FD table (LRU) -------- */
struct fd_key {
    __u32 tgid;
    __s32 fd;
};

struct fd_meta {
    __u8  kind;     // 0=unknown, 1=file, 2=socket
    __u8  family;   // AF_*
    __u8  proto;    // IPPROTO_*
    __u16 lport;    // local port (BE)
    __u32 laddr4;   // local ipv4 (BE)
    __u8  laddr6[16];
    __u16 rport;    // remote port (BE)
    __u32 raddr4;   // remote ipv4 (BE)
    __u8  raddr6[16];
    char  path[64]; // file path or memfd name (trunc)
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct fd_key);
    __type(value, struct fd_meta);
} edr_fd_table SEC(".maps");

/* -------- pending state between enter/exit -------- */
struct pending_open {
    char  path[128];
    __u32 flags;
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);           // pid_tgid
    __type(value, struct pending_open);
} edr_pending_open SEC(".maps");

struct pending_socket {
    __s32 domain;
    __s32 type;
    __s32 proto;
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);           // pid_tgid
    __type(value, struct pending_socket);
} edr_pending_socket SEC(".maps");

struct pending_accept {
    __u8  fam;
    __u8  proto;
    __u16 rport;
    __u32 raddr4;
    __u8  raddr6[16];
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);           // pid_tgid
    __type(value, struct pending_accept);
} edr_pending_accept SEC(".maps");

struct pending_clone {
    __u64 flags;
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);           // pid_tgid
    __type(value, struct pending_clone);
} edr_pending_clone SEC(".maps");

/*
 * -------- userland event --------
 * IMPORTANT:
 *  - Natural 8-byte alignment is required by libbpf ringbuf.
 *  - abi_version and event_size are mandatory first fields for version negotiation.
 *  - On x86_64 this layout is 384 bytes; the Rust mirror must match.
 *  - Keep field order; add new fields only at the end to preserve ABI.
 */
struct edr_event {
    /* ABI Safety (version negotiation) */
    __u32 abi_version; // MUST be 1 for this definition
    __u32 event_size;  // MUST be 384 for this definition

    __u64 ts;          // ktime_ns
    __u32 type;        // edr_evt_type
    __u32 syscall_id;  // ctx->id

    __u32 tgid;        // process id (tgid)
    __u32 ppid;        // parent tgid
    __u32 uid;         // uid

    __s32 fd;          // relevant fd (if any)
    __s32 ret;         // syscall return (on exit events)

    __u32 flags;       // O_* / PROT_* / PR_* / CLONE_* / etc.
    __u32 aux_u32;     // misc (e.g., bpf cmd)
    __u64 aux_u64;     // misc (e.g., len) — keeps 8B alignment

    /* networking */
    __u8  fam;         // AF_*
    __u8  proto;       // IPPROTO_*
    __u16 lport;       // local port (BE)
    __u32 laddr4;      // local ipv4 (BE)
    __u8  laddr6[16];
    __u16 rport;       // remote port (BE)
    __u32 raddr4;      // remote ipv4 (BE)
    __u8  raddr6[16];

    /* paths */
    char  path[128];   // primary path (e.g., exec/open src)
    char  path2[128];  // secondary path (e.g., rename dst)

    char  comm[16];    // task comm
} __attribute__((aligned(8)));    // ensure ringbuf-friendly alignment

/* Hard guard for drift on 64-bit builds (Rust side must match 384 bytes). */
#if __SIZEOF_LONG__ == 8
_Static_assert(sizeof(struct edr_event) == 384, "struct edr_event must be 384 bytes on x86_64");
#endif

static __always_inline __u32 edr_tgid(void) { return (__u32)(bpf_get_current_pid_tgid() >> 32); }
static __always_inline __u32 edr_pid(void)  { return (__u32)(bpf_get_current_pid_tgid()); }
static __always_inline __u32 edr_uid(void)  { return (__u32)(bpf_get_current_uid_gid()); }

static __always_inline void edr_ppid_uid_comm(__u32 *ppid_out, char comm[16]) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    __u32 ppid = parent ? BPF_CORE_READ(parent, tgid) : 0;
    *ppid_out = ppid;
    bpf_get_current_comm(comm, 16);
}

static __always_inline int edr_emit(struct edr_event *e) {
    /* ABI negotiation fields */
    e->abi_version = 1;
    e->event_size = 384;
    
    e->ts   = bpf_ktime_get_ns();
    e->uid  = edr_uid();
    edr_ppid_uid_comm(&e->ppid, e->comm);
    
    int ret = bpf_ringbuf_output(&edr_events_rb, e, sizeof(*e), 0);
    if (ret == 0) {
        __u32 key = 0;
        __u64 *count = bpf_map_lookup_elem(&edr_events_reserved, &key);
        if (count) __sync_fetch_and_add(count, 1);
    } else {
        __u32 key = 0;
        __u64 *count = bpf_map_lookup_elem(&edr_rb_reserve_failed, &key);
        if (count) __sync_fetch_and_add(count, 1);
    }
    return ret;
}

static __always_inline bool edr_allowed(__u32 id) {
    __u8 *v = bpf_map_lookup_elem(&edr_allow_syscalls, &id);
    return v && *v == 1;
}

static __always_inline void edr_copy_user_str(char *dst, const char *user, __u32 max) {
    if (!user || !max) return;
    bpf_probe_read_user_str(dst, max, user);
}

static __always_inline bool edr_should_sample(__u32 type, __u32 pid, bool is_root) {
    // Always log root
    if (is_root) return true;

    __u32 sample_rate = 1;  // Default: always log

    // Noisy hooks: sample based on type
    if (type == EVT_OPEN)      sample_rate = 100;
    if (type == EVT_WRITE)     sample_rate = 10000;
    if (type == EVT_READ)      sample_rate = 100000;
    if (type == EVT_BIND)      sample_rate = 10;
    if (type == EVT_CONNECT)   sample_rate = 100;
    if (type == EVT_SENDTO)    sample_rate = 1000;
    if (type == EVT_SENDMSG)   sample_rate = 1000;
    if (type == EVT_TCP_RETRANS) sample_rate = -1;  // Disabled (0)

    if (sample_rate <= 0) return false;
    if (sample_rate == 1) return true;

    // Increment and check sample counter
    __u64 *counter = bpf_map_lookup_elem(&edr_sample_counters, &pid);
    __u64 count = 0;
    if (counter) {
        count = __sync_fetch_and_add(counter, 1);
    }

    return (count % sample_rate) == 0;
}

#endif /* __EDR_EVENTS_H */
