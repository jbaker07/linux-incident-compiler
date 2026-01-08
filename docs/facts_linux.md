# Linux Facts Reference

This document maps Linux telemetry sources to their canonical Fact types used by the detection pipeline.

## Telemetry Source → Fact Type Mapping

### Process Events (FactType: Exec / ProcSpawn)

| Source | Event/Syscall | Description |
|--------|---------------|-------------|
| auditd | SYSCALL execve | Process execution |
| auditd | SYSCALL execveat | Process execution (with fd) |
| auditd | SYSCALL fork | Process fork |
| auditd | SYSCALL clone | Process clone |
| auditd | SYSCALL clone3 | Process clone (new API) |
| eBPF | tracepoint:syscalls:sys_enter_execve | Exec syscall entry |
| eBPF | tracepoint:sched:sched_process_exec | Process exec completion |
| eBPF | tracepoint:sched:sched_process_fork | Fork completion |
| procfs | /proc/[pid]/exe, cmdline, status | Process snapshot |

### File Events (FactType: WritePath / ReadPath / CreatePath / DeletePath)

| Source | Event/Syscall | Description |
|--------|---------------|-------------|
| auditd | SYSCALL open/openat | File open (check flags for R/W) |
| auditd | SYSCALL creat | File creation |
| auditd | SYSCALL write/pwrite64 | File write |
| auditd | SYSCALL read/pread64 | File read |
| auditd | SYSCALL unlink/unlinkat | File deletion |
| auditd | SYSCALL rename/renameat | File rename |
| auditd | PATH record | File path details |
| eBPF | kprobe:security_file_open | File access via LSM hook |
| eBPF | tracepoint:syscalls:sys_enter_openat | Open syscall |

### Network Events (FactType: OutboundConnect / InboundAccept / DnsResolve)

| Source | Event/Syscall | Description |
|--------|---------------|-------------|
| auditd | SYSCALL connect | Outbound connection |
| auditd | SYSCALL accept/accept4 | Inbound connection |
| auditd | SYSCALL socket | Socket creation |
| auditd | SYSCALL bind | Socket bind |
| auditd | SYSCALL listen | Socket listen |
| auditd | SOCKADDR record | Socket address details |
| eBPF | kprobe:tcp_connect | TCP connect |
| eBPF | kprobe:tcp_v4_connect | IPv4 TCP connect |
| eBPF | kprobe:tcp_v6_connect | IPv6 TCP connect |
| eBPF | tracepoint:syscalls:sys_enter_connect | Connect syscall |
| procfs | /proc/net/tcp, /proc/net/tcp6 | Active connections |

### Authentication Events (FactType: AuthEvent)

| Source | Log Pattern | Description |
|--------|-------------|-------------|
| journald | sshd.service: "Accepted" | SSH login success |
| journald | sshd.service: "Failed password" | SSH login failure |
| journald | sudo[*]: | Sudo invocation |
| auditd | USER_AUTH | User authentication attempt |
| auditd | USER_ACCT | User account status check |
| auditd | CRED_ACQ | Credential acquisition |
| auditd | USER_LOGIN | User login |
| auditd | USER_START | User session start |
| auditd | USER_END | User session end |
| auditd | USER_CMD | Sudo command execution |
| /var/log/auth.log | pam_unix patterns | PAM authentication |

### Persistence Events (FactType: PersistArtifact)

| Source | Path/Pattern | Description |
|--------|--------------|-------------|
| auditd/inotify | /etc/cron.d/* | Cron job creation |
| auditd/inotify | /var/spool/cron/* | User crontabs |
| auditd/inotify | /etc/crontab | System crontab |
| auditd/inotify | /etc/systemd/system/* | Systemd units |
| auditd/inotify | ~/.config/systemd/user/* | User systemd units |
| auditd/inotify | /etc/init.d/* | SysV init scripts |
| auditd/inotify | /etc/rc.local | rc.local script |
| journald | systemd: "Created" unit | Systemd unit creation |

### Privilege Escalation Events (FactType: PrivilegeBoundary)

| Source | Event/Syscall | Description |
|--------|---------------|-------------|
| auditd | SYSCALL setuid/setgid | UID/GID change |
| auditd | SYSCALL setreuid/setregid | Real/effective UID change |
| auditd | SYSCALL setresuid/setresgid | Full UID triplet change |
| auditd | SYSCALL prctl (PR_SET_SECUREBITS) | Security bits modification |
| auditd | SYSCALL capset | Capability modification |
| eBPF | kprobe:commit_creds | Credential commit |
| procfs | /proc/[pid]/status (Cap*) | Process capabilities |

### Kernel Module Events (FactType: KernelModule)

| Source | Event/Syscall | Description |
|--------|---------------|-------------|
| auditd | SYSCALL init_module | Module load from memory |
| auditd | SYSCALL finit_module | Module load from file |
| auditd | SYSCALL delete_module | Module unload |
| journald | kernel: module loaded | Module load via dmesg |
| eBPF | kprobe:do_init_module | Module initialization |
| procfs | /proc/modules | Loaded modules |

### Memory Events (FactType: MemWX)

| Source | Event/Syscall | Description |
|--------|---------------|-------------|
| auditd | SYSCALL mmap (PROT_EXEC) | Executable memory mapping |
| auditd | SYSCALL mprotect | Memory protection change |
| auditd | SYSCALL memfd_create | Anonymous file creation |
| eBPF | kprobe:do_mmap | Memory mapping |
| eBPF | kprobe:mprotect_fixup | Protection change |

### Debug/Injection Events (FactType: DebugAttach / RemoteThread)

| Source | Event/Syscall | Description |
|--------|---------------|-------------|
| auditd | SYSCALL ptrace | Process trace/debug |
| auditd | SYSCALL process_vm_readv | Cross-process memory read |
| auditd | SYSCALL process_vm_writev | Cross-process memory write |
| eBPF | kprobe:ptrace_attach | Ptrace attachment |

### Log Tamper Events (FactType: LogCleared)

| Source | Event/Pattern | Description |
|--------|---------------|-------------|
| auditd | USER_CMD: journalctl --vacuum | Journal vacuum |
| auditd | PATH: /var/log/* DELETE | Log file deletion |
| journald | systemd-journald: Rotating | Journal rotation |
| inotify | /var/log/* unlink events | Log file removal |

## Tag Enrichment Rules

Events are enriched with tags based on their characteristics:

### Process Tags
- `exec` - Process execution events
- `fork` - Process fork/clone events  
- `lolbin` - Known Linux living-off-the-land binaries
- `shell` - Shell interpreter execution
- `script` - Script interpreter (python, perl, ruby)

### Network Tags
- `network` - Network-related syscalls
- `connect` - Outbound connection
- `accept` - Inbound connection
- `dns` - DNS resolution

### File Tags
- `file_write` - File modification
- `file_create` - File creation
- `file_delete` - File deletion
- `file_read` - File read (sensitive files only)
- `critical_file` - System critical file access

### Auth Tags
- `auth` - Authentication event
- `ssh` - SSH-related
- `sudo` - Sudo invocation
- `pam` - PAM authentication

### Persistence Tags
- `persistence` - Persistence mechanism
- `cron` - Cron job
- `systemd` - Systemd unit
- `init` - Init system

### Privilege Tags
- `privilege_escalation` - Privilege change
- `setuid` - SUID execution
- `capability` - Linux capability manipulation

## Field Extraction Functions

The following extraction functions are available in `os/linux/fact_extractor.rs`:

| Function | Input Tags | Output FactType |
|----------|------------|-----------------|
| `extract_process_fact()` | exec, process, execve | Exec |
| `extract_file_write_fact()` | file_write, write, creat | WritePath |
| `extract_file_read_fact()` | file_read, read | ReadPath |
| `extract_file_delete_fact()` | file_delete, unlink | DeletePath |
| `extract_file_rename_fact()` | rename, file_rename | CreatePath |
| `extract_network_fact()` | network, connect | OutboundConnect |
| `extract_inbound_network_fact()` | accept, listen | InboundAccept |
| `extract_auth_fact()` | auth, ssh, sudo, pam | AuthEvent |
| `extract_persistence_fact()` | persistence, cron, systemd | PersistArtifact |
| `extract_privilege_fact()` | privilege_escalation, setuid | PrivilegeBoundary |
| `extract_kernel_module_fact()` | kernel_module, kmod | KernelModule |
| `extract_module_load_fact()` | module_load, dlopen | ModuleLoad |
| `extract_memory_fact()` | memory, mmap, mprotect | MemWX |
| `extract_ptrace_fact()` | ptrace, debug | DebugAttach |
| `extract_log_tamper_fact()` | log_tamper, log_cleared | LogCleared |
| `extract_dns_fact()` | dns, dns_query | DnsResolve |

## Linux LOLBins

The following binaries are classified as Linux "Living off the Land" binaries:

### Shells
`bash`, `sh`, `dash`, `zsh`, `ksh`, `csh`, `tcsh`, `fish`

### Interpreters
`python`, `python2`, `python3`, `perl`, `ruby`, `php`, `lua`, `node`, `nodejs`

### File Transfer
`curl`, `wget`, `nc`, `netcat`, `ncat`, `socat`, `scp`, `rsync`, `sftp`, `ftp`

### Privilege Escalation
`sudo`, `su`, `pkexec`, `doas`

### Container/Namespace
`nsenter`, `unshare`, `chroot`, `docker`, `podman`, `kubectl`

### Network Tools
`ssh`, `ssh-keygen`, `openssl`, `nmap`, `tcpdump`, `iptables`

### Process Tools
`gdb`, `strace`, `ltrace`, `kill`, `pkill`

## Usage Example

```rust
use edr_locald::os::linux::{extract_facts, enrich_tags_from_linux_source, is_linux_lolbin};

// Parse a Linux event from auditd/eBPF
let event = parse_event(raw_telemetry)?;

// Extract canonical facts
let facts = extract_facts(&event);

// Check if executable is a LOLBin
if is_linux_lolbin(&exe_path) {
    // Apply additional scrutiny
}
```

## See Also

- [Playbook Coverage](playbooks_linux_coverage.md) - Maps playbooks to required telemetry
- [UI Workflow](ui_workflow.md) - Using the detection engineer UI
- [facts_windows.md](facts_windows.md) - Windows equivalent documentation
