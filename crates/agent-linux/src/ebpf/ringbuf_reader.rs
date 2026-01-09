// crates/agent-linux/src/ebpf/ringbuf_reader.rs
//
// CO-RE ringbuf reader for eBPF maps.
// Subscribes to pinned ringbuf maps and dispatches events.

#![cfg(target_os = "linux")]

#[cfg(feature = "with-ebpf")]
use std::sync::Arc;
#[cfg(feature = "with-ebpf")]
use std::thread;
#[cfg(feature = "with-ebpf")]
use std::time::Duration;

/// Reader configuration
#[derive(Clone)]
pub struct RingbufConfig {
    /// BPF pin prefix (default: /sys/fs/bpf/edr)
    pub pin_prefix: String,
    /// Poll interval in milliseconds
    pub poll_ms: u64,
}

impl Default for RingbufConfig {
    fn default() -> Self {
        Self {
            pin_prefix: std::env::var("EDR_PIN_PREFIX")
                .unwrap_or_else(|_| "/sys/fs/bpf/edr".to_string()),
            poll_ms: 10,
        }
    }
}

/// Ringbuf reader handle
pub struct RingbufReader {
    config: RingbufConfig,
}

impl RingbufReader {
    pub fn new(config: RingbufConfig) -> Self {
        Self { config }
    }

    /// Check if pins are available
    pub fn pins_available(&self) -> bool {
        let base = self.config.pin_prefix.trim_end_matches('/');
        let path = format!("{}/edr_events_rb", base);
        std::path::Path::new(&path).exists()
    }

    /// Start reading from pinned ringbuf map
    #[cfg(feature = "with-ebpf")]
    pub fn start<F>(&self, map_name: &str, on_event: F) -> Result<(), String>
    where
        F: Fn(&[u8]) + Send + 'static,
    {
        use libbpf_rs::libbpf_sys as sys;
        use std::ffi::c_void;
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

        let base = self.config.pin_prefix.trim_end_matches('/');
        let map_path = format!("{}/{}", base, map_name);

        if !std::path::Path::new(&map_path).exists() {
            return Err(format!("pinned map not found: {}", map_path));
        }

        // Open BPF map by path
        let fd = {
            use std::ffi::CString;
            let cpath =
                CString::new(map_path.as_str()).map_err(|e| format!("CString error: {}", e))?;
            let fd = unsafe { sys::bpf_obj_get(cpath.as_ptr()) };
            if fd < 0 {
                return Err(format!(
                    "bpf_obj_get({}) failed: {}",
                    map_path,
                    std::io::Error::last_os_error()
                ));
            }
            unsafe { OwnedFd::from_raw_fd(fd) }
        };

        // Callback wrapper
        unsafe extern "C" fn rb_callback(ctx: *mut c_void, data: *mut c_void, size: u64) -> i32 {
            let cb = &mut *(ctx as *mut Box<dyn FnMut(&[u8]) + Send>);
            let slice = std::slice::from_raw_parts(data as *const u8, size as usize);
            cb(slice);
            0
        }

        // Box the closure
        let mut cb: Box<dyn FnMut(&[u8]) + Send> = Box::new(on_event);
        let ctx_ptr = Box::into_raw(Box::new(cb)) as *mut c_void;

        // Create ringbuffer
        let rb = unsafe {
            sys::ring_buffer__new(
                fd.as_raw_fd(),
                Some(rb_callback),
                ctx_ptr,
                std::ptr::null_mut(),
            )
        };

        if rb.is_null() {
            unsafe {
                drop(Box::from_raw(ctx_ptr as *mut Box<dyn FnMut(&[u8]) + Send>));
            }
            return Err(format!(
                "ring_buffer__new({}) failed: {}",
                map_path,
                std::io::Error::last_os_error()
            ));
        }

        // Keep FD alive
        let _leak_fd: &'static mut OwnedFd = Box::leak(Box::new(fd));

        let rb_usize = rb as usize;
        let path_owned = map_path.clone();
        let poll_ms = self.config.poll_ms;

        // Spawn polling thread
        thread::spawn(move || loop {
            let rb_ptr = rb_usize as *mut sys::ring_buffer;
            let rc = unsafe { sys::ring_buffer__poll(rb_ptr, poll_ms as i32) };
            if rc < 0 {
                eprintln!(
                    "ringbuf poll error on {}: {}",
                    path_owned,
                    std::io::Error::last_os_error()
                );
                thread::sleep(Duration::from_millis(50));
            }
        });

        log::info!("ringbuf subscriber active → {}", map_path);
        Ok(())
    }

    /// Stub for non-Linux or feature disabled
    #[cfg(not(feature = "with-ebpf"))]
    pub fn start<F>(&self, map_name: &str, _on_event: F) -> Result<(), String>
    where
        F: Fn(&[u8]) + Send + 'static,
    {
        log::warn!("eBPF feature disabled; cannot subscribe to {}", map_name);
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
pub struct RingbufReader;

#[cfg(not(target_os = "linux"))]
impl RingbufReader {
    pub fn new(_config: RingbufConfig) -> Self {
        Self
    }

    pub fn pins_available(&self) -> bool {
        false
    }

    pub fn start<F>(&self, _map_name: &str, _on_event: F) -> Result<(), String>
    where
        F: Fn(&[u8]) + Send + 'static,
    {
        Err("eBPF only available on Linux".to_string())
    }
}
