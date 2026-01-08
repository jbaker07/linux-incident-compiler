# Linux Playbook Coverage Matrix

This document provides MITRE ATT&CK technique coverage for Linux playbooks.

## Coverage Summary

| Category | Playbooks | Techniques Covered |
|----------|-----------|-------------------|
| Execution | 7 | T1059.004, T1053.003, T1204 |
| Persistence | 8 | T1136, T1543.002, T1053.003, T1546 |
| Privilege Escalation | 5 | T1548.001, T1068, T1055 |
| Defense Evasion | 6 | T1070, T1562, T1027 |
| Credential Access | 4 | T1003, T1552, T1110 |
| Discovery | 4 | T1082, T1083, T1057, T1016 |
| Lateral Movement | 3 | T1021.004, T1570 |
| Collection | 2 | T1560, T1074 |
| Command & Control | 4 | T1071, T1095, T1105 |
| Exfiltration | 2 | T1041, T1048 |
| Impact | 3 | T1485, T1490, T1489 |

**Total: 31 playbooks covering 45+ techniques**

---

## Playbook Details

### Execution Playbooks

#### `suspicious_shell_spawn.yaml`
- **MITRE ID:** T1059.004 (Command and Scripting Interpreter: Unix Shell)
- **Required Facts:** Exec
- **Slot Pattern:**
  - `process.name` in [bash, sh, dash, zsh, ksh]
  - `parent.name` in [httpd, nginx, apache2, java, node]
- **Telemetry:** auditd execve, eBPF sched_process_exec

#### `python_reverse_shell.yaml`
- **MITRE ID:** T1059.006 (Python)
- **Required Facts:** Exec, OutboundConnect
- **Slot Pattern:**
  - `process.name` matches python[23]?
  - `process.cmdline` contains socket or subprocess
- **Telemetry:** auditd execve, connect

#### `cron_command_execution.yaml`
- **MITRE ID:** T1053.003 (Scheduled Task/Job: Cron)
- **Required Facts:** Exec, ProcSpawn
- **Slot Pattern:**
  - `parent.name` == "cron"
  - `process.cmdline` exists
- **Telemetry:** auditd execve, journald crond

#### `curl_wget_download.yaml`
- **MITRE ID:** T1204.002 (User Execution: Malicious File)
- **Required Facts:** Exec, OutboundConnect, WritePath
- **Slot Pattern:**
  - `process.name` in [curl, wget]
  - `file.path` matches /tmp or /var/tmp
- **Telemetry:** auditd execve, connect, write

#### `base64_decode_execution.yaml`
- **MITRE ID:** T1059 (Command and Scripting Interpreter)
- **Required Facts:** Exec
- **Slot Pattern:**
  - `process.cmdline` contains "base64 -d"
  - `process.cmdline` pipes to shell
- **Telemetry:** auditd execve

#### `at_job_execution.yaml`
- **MITRE ID:** T1053.002 (At)
- **Required Facts:** Exec
- **Slot Pattern:**
  - `process.name` == "at" or "atd"
- **Telemetry:** auditd execve

#### `script_interpreter_spawn.yaml`
- **MITRE ID:** T1059 (Command and Scripting Interpreter)
- **Required Facts:** Exec
- **Slot Pattern:**
  - `process.name` in [perl, ruby, php, lua]
  - `process.cmdline` contains -e or inline code
- **Telemetry:** auditd execve

---

### Persistence Playbooks

#### `crontab_modification.yaml`
- **MITRE ID:** T1053.003 (Scheduled Task/Job: Cron)
- **Required Facts:** WritePath, PersistArtifact
- **Slot Pattern:**
  - `file.path` matches /var/spool/cron/* or /etc/cron*
- **Telemetry:** auditd write, inotify

#### `systemd_unit_creation.yaml`
- **MITRE ID:** T1543.002 (Systemd Service)
- **Required Facts:** WritePath, PersistArtifact
- **Slot Pattern:**
  - `file.path` matches /etc/systemd/system/*.service
  - `file.path` matches ~/.config/systemd/user/*
- **Telemetry:** auditd write, journald systemd

#### `bashrc_modification.yaml`
- **MITRE ID:** T1546.004 (Unix Shell Configuration Modification)
- **Required Facts:** WritePath
- **Slot Pattern:**
  - `file.path` matches ~/.bashrc, ~/.bash_profile, /etc/profile
- **Telemetry:** auditd write

#### `ssh_authorized_keys.yaml`
- **MITRE ID:** T1098.004 (SSH Authorized Keys)
- **Required Facts:** WritePath
- **Slot Pattern:**
  - `file.path` matches ~/.ssh/authorized_keys
- **Telemetry:** auditd write

#### `rc_local_modification.yaml`
- **MITRE ID:** T1037.004 (RC Scripts)
- **Required Facts:** WritePath, PersistArtifact
- **Slot Pattern:**
  - `file.path` == /etc/rc.local
- **Telemetry:** auditd write

#### `init_script_creation.yaml`
- **MITRE ID:** T1037.004 (RC Scripts)
- **Required Facts:** WritePath, PersistArtifact
- **Slot Pattern:**
  - `file.path` matches /etc/init.d/*
- **Telemetry:** auditd write

#### `user_creation.yaml`
- **MITRE ID:** T1136.001 (Create Account: Local Account)
- **Required Facts:** Exec, AuthEvent
- **Slot Pattern:**
  - `process.name` in [useradd, adduser]
- **Telemetry:** auditd execve, USER_ACCT

#### `motd_modification.yaml`
- **MITRE ID:** T1546.003 (Message of the Day)
- **Required Facts:** WritePath
- **Slot Pattern:**
  - `file.path` matches /etc/update-motd.d/*
- **Telemetry:** auditd write

---

### Privilege Escalation Playbooks

#### `sudo_abuse.yaml`
- **MITRE ID:** T1548.003 (Abuse Elevation Control Mechanism: Sudo)
- **Required Facts:** Exec, PrivilegeBoundary
- **Slot Pattern:**
  - `process.name` == "sudo"
  - `user.id` changes 0
- **Telemetry:** auditd execve, USER_CMD

#### `suid_binary_execution.yaml`
- **MITRE ID:** T1548.001 (Setuid and Setgid)
- **Required Facts:** Exec, PrivilegeBoundary
- **Slot Pattern:**
  - `file.mode` has SUID bit
  - `process.ruid` != `process.euid`
- **Telemetry:** auditd execve, PATH record

#### `pkexec_execution.yaml`
- **MITRE ID:** T1548.003 (Sudo and Sudo Caching)
- **Required Facts:** Exec, PrivilegeBoundary
- **Slot Pattern:**
  - `process.name` == "pkexec"
- **Telemetry:** auditd execve

#### `capability_modification.yaml`
- **MITRE ID:** T1068 (Exploitation for Privilege Escalation)
- **Required Facts:** PrivilegeBoundary
- **Slot Pattern:**
  - `syscall` == "capset"
- **Telemetry:** auditd capset

#### `kernel_exploit_indicators.yaml`
- **MITRE ID:** T1068 (Exploitation for Privilege Escalation)
- **Required Facts:** PrivilegeBoundary, MemWX
- **Slot Pattern:**
  - `process.uid` changes suddenly to 0
  - Memory RWX mapping detected
- **Telemetry:** auditd setuid, mmap/mprotect

---

### Defense Evasion Playbooks

#### `log_deletion.yaml`
- **MITRE ID:** T1070.002 (Clear Linux or Mac System Logs)
- **Required Facts:** DeletePath, LogCleared
- **Slot Pattern:**
  - `file.path` matches /var/log/*
- **Telemetry:** auditd unlink

#### `history_clearing.yaml`
- **MITRE ID:** T1070.003 (Clear Command History)
- **Required Facts:** DeletePath, WritePath
- **Slot Pattern:**
  - `file.path` matches ~/.bash_history or HISTFILE
  - `process.cmdline` contains "history -c"
- **Telemetry:** auditd unlink/write

#### `timestomp.yaml`
- **MITRE ID:** T1070.006 (Timestomp)
- **Required Facts:** Exec
- **Slot Pattern:**
  - `process.name` == "touch"
  - `process.cmdline` contains -t or -d
- **Telemetry:** auditd execve

#### `kernel_module_loading.yaml`
- **MITRE ID:** T1547.006 (Kernel Modules and Extensions)
- **Required Facts:** KernelModule
- **Slot Pattern:**
  - `syscall` in [init_module, finit_module]
- **Telemetry:** auditd init_module, journald kernel

#### `process_injection_ptrace.yaml`
- **MITRE ID:** T1055.008 (Ptrace System Calls)
- **Required Facts:** DebugAttach
- **Slot Pattern:**
  - `syscall` == "ptrace"
  - `ptrace.request` == PTRACE_ATTACH or PTRACE_POKETEXT
- **Telemetry:** auditd ptrace

#### `ld_preload_injection.yaml`
- **MITRE ID:** T1574.006 (Dynamic Linker Hijacking)
- **Required Facts:** Exec, ModuleLoad
- **Slot Pattern:**
  - Environment contains LD_PRELOAD
  - `file.path` matches /etc/ld.so.preload
- **Telemetry:** auditd execve, write

---

### Credential Access Playbooks

#### `etc_shadow_access.yaml`
- **MITRE ID:** T1003.008 (/etc/passwd and /etc/shadow)
- **Required Facts:** ReadPath
- **Slot Pattern:**
  - `file.path` == /etc/shadow
  - `process.name` not in [passwd, chpasswd, pam*]
- **Telemetry:** auditd read

#### `ssh_key_theft.yaml`
- **MITRE ID:** T1552.004 (Private Keys)
- **Required Facts:** ReadPath
- **Slot Pattern:**
  - `file.path` matches ~/.ssh/id_*
  - `file.path` matches /etc/ssh/*_key
- **Telemetry:** auditd read

#### `proc_memory_dump.yaml`
- **MITRE ID:** T1003.007 (Proc Filesystem)
- **Required Facts:** ReadPath
- **Slot Pattern:**
  - `file.path` matches /proc/*/maps or /proc/*/mem
- **Telemetry:** auditd read

#### `mimipenguin_patterns.yaml`
- **MITRE ID:** T1003 (OS Credential Dumping)
- **Required Facts:** Exec, ReadPath
- **Slot Pattern:**
  - Process reads /proc/*/maps AND /proc/*/mem
  - GDB patterns against sshd/gnome-keyring
- **Telemetry:** auditd execve, read

---

### Discovery Playbooks

#### `system_info_enumeration.yaml`
- **MITRE ID:** T1082 (System Information Discovery)
- **Required Facts:** Exec
- **Slot Pattern:**
  - `process.name` in [uname, hostnamectl, lscpu, dmidecode]
- **Telemetry:** auditd execve

#### `network_discovery.yaml`
- **MITRE ID:** T1016 (System Network Configuration Discovery)
- **Required Facts:** Exec
- **Slot Pattern:**
  - `process.name` in [ifconfig, ip, netstat, ss, route]
- **Telemetry:** auditd execve

#### `process_discovery.yaml`
- **MITRE ID:** T1057 (Process Discovery)
- **Required Facts:** Exec, ReadPath
- **Slot Pattern:**
  - `process.name` == "ps"
  - Reading /proc/*/cmdline
- **Telemetry:** auditd execve, read

#### `file_discovery.yaml`
- **MITRE ID:** T1083 (File and Directory Discovery)
- **Required Facts:** Exec
- **Slot Pattern:**
  - `process.name` in [find, locate, ls]
  - Targeting sensitive directories
- **Telemetry:** auditd execve

---

### Lateral Movement Playbooks

#### `ssh_connection_outbound.yaml`
- **MITRE ID:** T1021.004 (Remote Services: SSH)
- **Required Facts:** Exec, OutboundConnect
- **Slot Pattern:**
  - `process.name` == "ssh"
  - Outbound port 22
- **Telemetry:** auditd execve, connect

#### `scp_file_transfer.yaml`
- **MITRE ID:** T1570 (Lateral Tool Transfer)
- **Required Facts:** Exec, OutboundConnect
- **Slot Pattern:**
  - `process.name` == "scp"
- **Telemetry:** auditd execve, connect

#### `internal_port_scan.yaml`
- **MITRE ID:** T1046 (Network Service Discovery)
- **Required Facts:** OutboundConnect
- **Slot Pattern:**
  - Multiple connections to internal IPs
  - Sequential port access
- **Telemetry:** auditd connect, eBPF tcp_connect

---

### Command and Control Playbooks

#### `reverse_shell_detection.yaml`
- **MITRE ID:** T1071.001 (Application Layer Protocol)
- **Required Facts:** Exec, OutboundConnect
- **Slot Pattern:**
  - Shell spawns with socket redirect
  - Stdin/stdout/stderr to network
- **Telemetry:** auditd execve, connect

#### `dns_tunneling.yaml`
- **MITRE ID:** T1071.004 (DNS)
- **Required Facts:** DnsResolve
- **Slot Pattern:**
  - High volume TXT queries
  - Long subdomain labels
- **Telemetry:** DNS packet capture

#### `unusual_outbound_port.yaml`
- **MITRE ID:** T1571 (Non-Standard Port)
- **Required Facts:** OutboundConnect
- **Slot Pattern:**
  - Connection on high port
  - Non-standard service port
- **Telemetry:** auditd connect

#### `tor_connection.yaml`
- **MITRE ID:** T1090.003 (Proxy: Multi-hop Proxy)
- **Required Facts:** OutboundConnect
- **Slot Pattern:**
  - Connection to known Tor ports (9001, 9050, 9150)
  - Connection to Tor directory authorities
- **Telemetry:** auditd connect

---

### Exfiltration Playbooks

#### `data_exfil_curl_post.yaml`
- **MITRE ID:** T1041 (Exfiltration Over C2 Channel)
- **Required Facts:** Exec, OutboundConnect, ReadPath
- **Slot Pattern:**
  - curl with -X POST or --data
  - Prior sensitive file read
- **Telemetry:** auditd execve, connect, read

#### `data_staging.yaml`
- **MITRE ID:** T1074 (Data Staged)
- **Required Facts:** WritePath
- **Slot Pattern:**
  - Writes to /tmp, /var/tmp, /dev/shm
  - Archive creation (tar, zip)
- **Telemetry:** auditd write

---

### Impact Playbooks

#### `ransomware_indicators.yaml`
- **MITRE ID:** T1486 (Data Encrypted for Impact)
- **Required Facts:** WritePath, DeletePath
- **Slot Pattern:**
  - Mass file writes with encryption extensions
  - Original files deleted
- **Telemetry:** auditd write, unlink

#### `data_destruction.yaml`
- **MITRE ID:** T1485 (Data Destruction)
- **Required Facts:** Exec, DeletePath
- **Slot Pattern:**
  - `process.name` in [rm, shred, wipe]
  - Recursive deletion of critical paths
- **Telemetry:** auditd execve, unlink

#### `service_stop.yaml`
- **MITRE ID:** T1489 (Service Stop)
- **Required Facts:** Exec
- **Slot Pattern:**
  - `process.name` in [systemctl, service]
  - `cmdline` contains "stop" or "disable"
- **Telemetry:** auditd execve, journald systemd

---

## Required Telemetry Sources

To achieve full coverage, enable the following:

### auditd Rules (Essential)
```bash
# Execution monitoring
-a always,exit -F arch=b64 -S execve -F key=exec

# File access - credentials
-a always,exit -F arch=b64 -S open,openat -F path=/etc/shadow -F key=shadow
-a always,exit -F arch=b64 -S open,openat -F path=/etc/passwd -F key=passwd

# Network
-a always,exit -F arch=b64 -S connect -F key=network
-a always,exit -F arch=b64 -S accept,accept4 -F key=network

# Persistence paths
-a always,exit -F arch=b64 -S open,openat,creat -F dir=/etc/cron.d -F key=cron
-a always,exit -F arch=b64 -S open,openat,creat -F dir=/etc/systemd/system -F key=systemd

# Privilege escalation
-a always,exit -F arch=b64 -S setuid,setgid,setreuid,setregid -F key=privesc

# Kernel modules
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -F key=kmod
```

### journald (Essential)
- sshd.service - Authentication events
- sudo - Privilege escalation
- systemd - Service management
- auditd - Audit daemon events

### Optional eBPF Tracepoints
- sched:sched_process_exec
- sched:sched_process_fork
- syscalls:sys_enter_connect
- syscalls:sys_enter_openat

## Coverage Gaps

The following ATT&CK techniques have limited or no coverage:

| Technique | Reason | Mitigation |
|-----------|--------|------------|
| T1134 (Access Token Manipulation) | Linux-specific token handling differs | Monitor setuid family |
| T1055.001 (DLL Injection) | Windows-specific; use LD_PRELOAD on Linux | Covered by ld_preload_injection |
| T1218 (Signed Binary Proxy Execution) | Windows-specific | Linux LOLBins partially covered |
| T1087 (Account Discovery) | Passive reads hard to track | Monitor /etc/passwd reads |

---

## See Also

- [facts_linux.md](facts_linux.md) - Telemetry source to Fact mapping
- [facts_windows.md](facts_windows.md) - Windows playbook coverage
- [SHIP_CHECKLIST.md](../SHIP_CHECKLIST.md) - Release requirements
