// crates/agent-linux/src/ebpf/ebpf_bridge.rs
//
// Translate raw kernel eBPF events into edr-core Event structures.
// This maps syscall/tracepoint data into the unified run-contract format.

#![allow(dead_code)]

use edr_core::Event;
use std::collections::BTreeMap;

/// Event type constants - must match eBPF C headers (edr_events.h)
pub mod evt {
    pub const EVT_EXEC: u32 = 30;
    pub const EVT_OPEN: u32 = 10;
    pub const EVT_RENAME: u32 = 11;
    pub const EVT_READ: u32 = 12;
    pub const EVT_WRITE: u32 = 13;
    pub const EVT_UNLINK: u32 = 14;
    pub const EVT_CHMOD_CHOWN: u32 = 15;
    pub const EVT_SETXATTR: u32 = 16;
    pub const EVT_CLOSE: u32 = 18;
    pub const EVT_DUP: u32 = 19;

    pub const EVT_SOCKET: u32 = 20;
    pub const EVT_CONNECT: u32 = 21;
    pub const EVT_BIND: u32 = 22;
    pub const EVT_LISTEN: u32 = 23;
    pub const EVT_ACCEPT: u32 = 24;
    pub const EVT_SENDTO: u32 = 25;
    pub const EVT_SENDMSG: u32 = 26;
    pub const EVT_RECVFROM: u32 = 27;
    pub const EVT_RECVMSG: u32 = 28;

    pub const EVT_MPROTECT: u32 = 40;
    pub const EVT_MEMFD_CREATE: u32 = 42;

    pub const EVT_SETUID: u32 = 50;
    pub const EVT_CAPSET: u32 = 51;

    pub const EVT_CLONE: u32 = 60;
    pub const EVT_PTRACE: u32 = 62;
    pub const EVT_PRCTL: u32 = 63;
    pub const EVT_SECCOMP: u32 = 64;

    pub const EVT_SETNS: u32 = 70;
    pub const EVT_UNSHARE: u32 = 71;
    pub const EVT_MOUNT: u32 = 72;
    pub const EVT_UMOUNT2: u32 = 73;
    pub const EVT_PIVOT_ROOT: u32 = 74;

    pub const EVT_MOD_LOAD: u32 = 80;
    pub const EVT_MOD_DEL: u32 = 81;

    pub const EVT_BPF: u32 = 90;

    // Tracepoint add-ons
    pub const EVT_PROC_EXEC_TP: u32 = 101;
    pub const EVT_PROC_FORK: u32 = 102;
    pub const EVT_PROC_EXIT: u32 = 103;

    pub const EVT_TCP_STATE: u32 = 200;
    pub const EVT_TCP_RETRANS: u32 = 201;
}

/// Raw eBPF event structure - must match C layout exactly (376 bytes, 8-byte aligned)
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct EdREvent {
    pub ts: u64,           // ktime_ns (nanoseconds)
    pub type_: u32,        // edr_evt_type
    pub syscall_id: u32,

    pub tgid: u32,
    pub ppid: u32,
    pub uid: u32,

    pub fd: i32,
    pub ret: i32,

    pub flags: u32,
    pub aux_u32: u32,
    pub aux_u64: u64,

    // networking
    pub fam: u8,
    pub proto: u8,
    pub lport: u16,
    pub laddr4: u32,
    pub laddr6: [u8; 16],
    pub rport: u16,
    pub raddr4: u32,
    pub raddr6: [u8; 16],

    // paths
    pub path: [u8; 128],
    pub path2: [u8; 128],

    // comm
    pub comm: [u8; 16],
}

// ABI guard: compile-time check that struct size matches C side (376 bytes)
const _: [(); 376] = [(); core::mem::size_of::<EdREvent>()];

/// Convert C-style null-terminated bytes to String
fn cstr_trunc(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// Convert big-endian IPv4 to dotted string
fn ipv4_be_to_string(be: u32) -> String {
    let b = be.to_be_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

/// Convert big-endian port to host u16
fn port_be_to_u16(be: u16) -> u16 {
    u16::from_be(be)
}

/// Map event type to tags
fn tags_for_event(e: &EdREvent) -> Vec<String> {
    use evt::*;
    let mut t = vec!["linux".to_string()];

    match e.type_ {
        EVT_EXEC | EVT_PROC_EXEC_TP => t.push("process_exec".into()),
        EVT_OPEN => t.push("file_open".into()),
        EVT_RENAME => t.push("file_rename".into()),
        EVT_UNLINK => t.push("file_unlink".into()),
        EVT_CHMOD_CHOWN => t.push("file_perm".into()),
        EVT_SETXATTR => t.push("file_xattr".into()),
        EVT_CLOSE => t.push("fd_close".into()),
        EVT_DUP => t.push("fd_dup".into()),

        EVT_SOCKET => t.push("sock_create".into()),
        EVT_BIND => t.push("sock_bind".into()),
        EVT_LISTEN => t.push("sock_listen".into()),
        EVT_CONNECT => t.push("network_connection".into()),
        EVT_ACCEPT => t.push("net_accept".into()),
        EVT_SENDTO | EVT_SENDMSG => t.push("net_send".into()),
        EVT_RECVFROM | EVT_RECVMSG => t.push("net_recv".into()),
        EVT_TCP_STATE => t.push("tcp_state".into()),
        EVT_TCP_RETRANS => t.push("tcp_retrans".into()),

        EVT_MPROTECT => {
            t.push("mprotect".into());
            if e.flags & 0x4 != 0 {
                t.push("mprotect_exec".into());
            }
        }
        EVT_MEMFD_CREATE => t.push("memfd_create".into()),

        EVT_SETUID => t.push("priv_setuid".into()),
        EVT_CAPSET => t.push("priv_capset".into()),
        EVT_PTRACE => t.push("ptrace".into()),
        EVT_PRCTL => t.push("prctl".into()),
        EVT_SECCOMP => t.push("seccomp".into()),

        EVT_SETNS => t.push("ns_setns".into()),
        EVT_UNSHARE => t.push("ns_unshare".into()),
        EVT_MOUNT => t.push("fs_mount".into()),
        EVT_UMOUNT2 => t.push("fs_umount".into()),
        EVT_PIVOT_ROOT => t.push("fs_pivot_root".into()),

        EVT_MOD_LOAD => t.push("kernel_module_load".into()),
        EVT_MOD_DEL => t.push("kernel_module_delete".into()),
        EVT_BPF => t.push("bpf_usage".into()),

        EVT_CLONE => t.push("proc_clone".into()),
        EVT_PROC_FORK => t.push("proc_fork".into()),
        EVT_PROC_EXIT => t.push("proc_exit".into()),

        EVT_READ => t.push("fd_read".into()),
        EVT_WRITE => t.push("fd_write".into()),
        _ => t.push("unknown_evt".into()),
    }

    t
}

/// Read /proc/<pid>/cmdline
#[cfg(target_os = "linux")]
fn read_proc_cmdline(pid: i32) -> String {
    if pid <= 0 {
        return String::new();
    }
    let path = format!("/proc/{}/cmdline", pid);
    std::fs::read(path)
        .map(|bytes| {
            bytes
                .split(|b| *b == 0u8)
                .filter(|part| !part.is_empty())
                .map(|part| String::from_utf8_lossy(part).into_owned())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default()
}

#[cfg(not(target_os = "linux"))]
fn read_proc_cmdline(_pid: i32) -> String {
    String::new()
}

/// Read /proc/<pid>/cwd
#[cfg(target_os = "linux")]
fn read_proc_cwd(pid: i32) -> String {
    if pid <= 0 {
        return String::new();
    }
    let path = std::path::PathBuf::from(format!("/proc/{}/cwd", pid));
    std::fs::read_link(path)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

#[cfg(not(target_os = "linux"))]
fn read_proc_cwd(_pid: i32) -> String {
    String::new()
}

/// Get hostname
fn get_hostname() -> String {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/etc/hostname")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string())
    }
    #[cfg(not(target_os = "linux"))]
    {
        "unknown".to_string()
    }
}

/// Convert raw eBPF event to edr-core Event
pub fn edr_event_to_core_event(e: &EdREvent) -> Event {
    let ts_ms = (e.ts / 1_000_000) as i64; // nanoseconds to milliseconds
    let p1 = cstr_trunc(&e.path);
    let cmd = cstr_trunc(&e.comm);
    let tags = tags_for_event(e);

    // Build fields map
    let mut fields: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    fields.insert("ts_ns".into(), serde_json::json!(e.ts));
    fields.insert("pid".into(), serde_json::json!(e.tgid));
    fields.insert("ppid".into(), serde_json::json!(e.ppid));
    fields.insert("uid".into(), serde_json::json!(e.uid));
    fields.insert("euid".into(), serde_json::json!(e.uid)); // Same as uid for now
    fields.insert("fd".into(), serde_json::json!(e.fd));
    fields.insert("ret".into(), serde_json::json!(e.ret));
    fields.insert("evt_type".into(), serde_json::json!(e.type_));
    fields.insert("syscall_id".into(), serde_json::json!(e.syscall_id));
    fields.insert("flags".into(), serde_json::json!(e.flags));
    fields.insert("comm".into(), serde_json::json!(cmd.clone()));

    if !p1.is_empty() {
        fields.insert("path".into(), serde_json::json!(p1.clone()));
        fields.insert("exe".into(), serde_json::json!(p1.clone()));
    }
    let p2 = cstr_trunc(&e.path2);
    if !p2.is_empty() {
        fields.insert("path2".into(), serde_json::json!(p2));
    }

    // Network fields
    if e.fam != 0 {
        fields.insert("fam".into(), serde_json::json!(e.fam));
    }
    if e.lport != 0 {
        fields.insert("local_port".into(), serde_json::json!(port_be_to_u16(e.lport)));
    }
    if e.laddr4 != 0 {
        fields.insert("local_ip".into(), serde_json::json!(ipv4_be_to_string(e.laddr4)));
    }
    if e.rport != 0 {
        fields.insert("remote_port".into(), serde_json::json!(port_be_to_u16(e.rport)));
    }
    if e.raddr4 != 0 {
        fields.insert("remote_ip".into(), serde_json::json!(ipv4_be_to_string(e.raddr4)));
    }

    // Enrich with procfs
    let cmdline = read_proc_cmdline(e.tgid as i32);
    if !cmdline.is_empty() {
        fields.insert("command_line".into(), serde_json::json!(cmdline));
    }
    let cwd = read_proc_cwd(e.tgid as i32);
    if !cwd.is_empty() {
        fields.insert("cwd".into(), serde_json::json!(cwd));
    }

    // Generate process key
    let proc_key = Some(format!("{}:{}", e.tgid, e.ts));

    Event {
        ts_ms,
        host: get_hostname(),
        tags,
        proc_key,
        file_key: if !p1.is_empty() { Some(p1) } else { None },
        identity_key: None,
        evidence_ptr: None,
        fields,
    }
}

/// Parse raw bytes into EdREvent (if size matches)
pub fn parse_edr_event(bytes: &[u8]) -> Option<EdREvent> {
    if bytes.len() < std::mem::size_of::<EdREvent>() {
        return None;
    }
    // SAFETY: we checked the size; the struct is repr(C) with known alignment
    let e: EdREvent = unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const EdREvent) };
    Some(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edr_event_size() {
        assert_eq!(std::mem::size_of::<EdREvent>(), 376);
    }

    #[test]
    fn test_cstr_trunc() {
        let buf = b"hello\0world";
        assert_eq!(cstr_trunc(buf), "hello");
    }

    #[test]
    fn test_ipv4_conversion() {
        // 192.168.1.1 in big-endian
        let be = 0xC0A80101u32.to_be();
        assert_eq!(ipv4_be_to_string(be), "192.168.1.1");
    }
}
