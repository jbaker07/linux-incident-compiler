// crates/agent-linux/src/host.rs
//
// Linux host information collection via procfs/sysfs.

/// Host information structure
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HostInfo {
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub kernel_version: String,
    pub arch: String,
    pub cpu_count: usize,
    pub total_memory_kb: u64,
    pub boot_time_secs: u64,
    pub machine_id: String,
}

impl Default for HostInfo {
    fn default() -> Self {
        Self {
            hostname: String::new(),
            os_name: "Linux".to_string(),
            os_version: String::new(),
            kernel_version: String::new(),
            arch: std::env::consts::ARCH.to_string(),
            cpu_count: 0,
            total_memory_kb: 0,
            boot_time_secs: 0,
            machine_id: String::new(),
        }
    }
}

impl HostInfo {
    /// Collect host information from procfs/sysfs
    #[cfg(target_os = "linux")]
    pub fn collect() -> Self {
        use std::collections::HashMap;
        use std::fs;

        let mut info = Self::default();

        // Hostname
        info.hostname = fs::read_to_string("/etc/hostname")
            .map(|s| s.trim().to_string())
            .or_else(|_| {
                fs::read_to_string("/proc/sys/kernel/hostname")
                    .map(|s| s.trim().to_string())
            })
            .unwrap_or_else(|_| "unknown".to_string());

        // OS release info
        if let Ok(content) = fs::read_to_string("/etc/os-release") {
            let kv: HashMap<String, String> = content
                .lines()
                .filter_map(|line| {
                    let mut parts = line.splitn(2, '=');
                    let key = parts.next()?.to_string();
                    let value = parts.next()?.trim_matches('"').to_string();
                    Some((key, value))
                })
                .collect();

            info.os_name = kv.get("NAME").cloned().unwrap_or_else(|| "Linux".to_string());
            info.os_version = kv.get("VERSION_ID").cloned().unwrap_or_default();
        }

        // Kernel version
        info.kernel_version = fs::read_to_string("/proc/version")
            .map(|s| {
                s.split_whitespace()
                    .nth(2)
                    .unwrap_or("unknown")
                    .to_string()
            })
            .unwrap_or_else(|_| "unknown".to_string());

        // CPU count
        info.cpu_count = fs::read_to_string("/proc/cpuinfo")
            .map(|s| s.matches("processor").count())
            .unwrap_or(1);

        // Memory info
        if let Ok(meminfo) = fs::read_to_string("/proc/meminfo") {
            for line in meminfo.lines() {
                if line.starts_with("MemTotal:") {
                    if let Some(kb) = line
                        .split_whitespace()
                        .nth(1)
                        .and_then(|s| s.parse::<u64>().ok())
                    {
                        info.total_memory_kb = kb;
                        break;
                    }
                }
            }
        }

        // Boot time from /proc/stat
        if let Ok(stat) = fs::read_to_string("/proc/stat") {
            for line in stat.lines() {
                if line.starts_with("btime ") {
                    if let Some(btime) = line.split_whitespace().nth(1).and_then(|s| s.parse().ok())
                    {
                        info.boot_time_secs = btime;
                        break;
                    }
                }
            }
        }

        // Machine ID
        info.machine_id = fs::read_to_string("/etc/machine-id")
            .map(|s| s.trim().to_string())
            .or_else(|_| {
                fs::read_to_string("/var/lib/dbus/machine-id")
                    .map(|s| s.trim().to_string())
            })
            .unwrap_or_else(|_| uuid::Uuid::new_v4().to_string());

        info
    }

    /// Stub for non-Linux
    #[cfg(not(target_os = "linux"))]
    pub fn collect() -> Self {
        Self {
            hostname: "unknown".to_string(),
            machine_id: uuid::Uuid::new_v4().to_string(),
            ..Default::default()
        }
    }
}

/// Get list of network interfaces
#[cfg(target_os = "linux")]
pub fn list_network_interfaces() -> Vec<String> {
    use std::fs;
    use std::path::Path;

    let sys_net = Path::new("/sys/class/net");
    if !sys_net.exists() {
        return vec![];
    }

    fs::read_dir(sys_net)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().to_string())
                .filter(|name| name != "lo") // Exclude loopback
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(not(target_os = "linux"))]
pub fn list_network_interfaces() -> Vec<String> {
    vec![]
}

/// Check if running as root
pub fn is_root() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Check if eBPF is available (kernel >= 4.15 with CAP_BPF or root)
#[cfg(target_os = "linux")]
pub fn ebpf_available() -> bool {
    use std::fs;
    use std::path::Path;

    // Check for BTF (needed for CO-RE)
    let path = Path::new("/sys/kernel/btf/vmlinux");
    path.exists() || {
        // Fallback: check if /proc/kallsyms contains bpf entries
        fs::read_to_string("/proc/kallsyms")
            .map(|s| s.contains(" bpf_"))
            .unwrap_or(false)
    }
}

#[cfg(not(target_os = "linux"))]
pub fn ebpf_available() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_info_default() {
        let info = HostInfo::default();
        assert_eq!(info.os_name, "Linux");
        assert_eq!(info.arch, std::env::consts::ARCH);
    }
}

