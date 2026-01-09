// crates/agent-linux/src/bin/capture_linux_rotating.rs
//
// Linux rotating capture binary.
//
// Run contract output:
//   <output_dir>/
//     index.json          - run metadata + segment manifest
//     segments/
//       segment_000000.jsonl.gz
//       segment_000001.jsonl.gz
//       ...
//
// Usage:
//   capture_linux_rotating --output ./run [--duration 300] [--pin-prefix /sys/fs/bpf/edr]

#![cfg_attr(not(target_os = "linux"), allow(unused_imports, dead_code))]

use agent_linux::capture::{CaptureConfig, SharedCaptureWriter};
use agent_linux::host::HostInfo;
use clap::Parser;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Linux eBPF rotating capture agent
#[derive(Parser, Debug)]
#[command(name = "capture_linux_rotating")]
#[command(about = "Capture Linux kernel events via eBPF with rotating segments")]
struct Args {
    /// Output directory for run artifacts
    #[arg(short, long, default_value = "./run")]
    output: PathBuf,

    /// Capture duration in seconds (0 = indefinite)
    #[arg(short, long, default_value_t = 0)]
    duration: u64,

    /// Events per segment before rotation
    #[arg(long, default_value_t = 100_000)]
    events_per_segment: usize,

    /// Segment duration in seconds
    #[arg(long, default_value_t = 300)]
    segment_secs: u64,

    /// BPF pin prefix path
    #[arg(long, default_value = "/sys/fs/bpf/edr")]
    pin_prefix: String,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    use agent_linux::ebpf::{EbpfIngest, RingbufConfig, RingbufReader};
    use agent_linux::host::{ebpf_available, is_root};

    let args = Args::parse();

    // Initialize logging
    if args.verbose {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    } else {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    }

    // Check prerequisites
    if !is_root() {
        log::warn!("Not running as root - eBPF may not be available");
    }

    if !ebpf_available() {
        log::warn!("eBPF may not be available on this kernel");
    }

    // Collect host info
    let host = HostInfo::collect();
    log::info!("Host: {} ({})", host.hostname, host.kernel_version);

    // Create capture writer
    let config = CaptureConfig {
        output_dir: args.output.clone(),
        events_per_segment: args.events_per_segment,
        segment_duration_secs: args.segment_secs,
        max_segment_bytes: 50 * 1024 * 1024,
    };

    let writer = SharedCaptureWriter::new(config)?;
    log::info!("Run ID: {}", writer.run_id());
    log::info!("Output: {}", args.output.display());

    // Set up signal handling
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        log::info!("Received shutdown signal");
        r.store(false, Ordering::Relaxed);
    })?;

    // Set up eBPF ringbuf reader
    std::env::set_var("EDR_PIN_PREFIX", &args.pin_prefix);

    let reader_config = RingbufConfig {
        pin_prefix: args.pin_prefix.clone(),
        poll_ms: 10,
    };
    let reader = RingbufReader::new(reader_config);

    if reader.pins_available() {
        log::info!("Starting eBPF ringbuf reader from {}", args.pin_prefix);

        // Subscribe to edr_events_rb (main syscall/lifecycle events)
        let writer_clone = writer.clone();
        let ingest = EbpfIngest::new(move |event| {
            if let Err(e) = writer_clone.write_event(&event) {
                log::error!("Failed to write event: {}", e);
            }
        });
        let cb = ingest.make_callback();
        if let Err(e) = reader.start("edr_events_rb", cb) {
            log::error!("Failed to start edr_events_rb reader: {}", e);
        }

        // Subscribe to net_events (network flow)
        let writer_clone2 = writer.clone();
        let net_ingest = EbpfIngest::new(move |event| {
            if let Err(e) = writer_clone2.write_event(&event) {
                log::error!("Failed to write net event: {}", e);
            }
        });
        let net_cb = net_ingest.make_callback();
        if let Err(e) = reader.start("net_events", net_cb) {
            log::warn!("net_events not available: {}", e);
        }
    } else {
        log::error!("eBPF pins not found at {}", args.pin_prefix);
        log::error!("Hint: Run `edr_attach_any -p {}` first", args.pin_prefix);
        return Err(anyhow::anyhow!("eBPF pins not available"));
    }

    // Main loop
    let start = std::time::Instant::now();
    let duration_limit = if args.duration > 0 {
        Some(Duration::from_secs(args.duration))
    } else {
        None
    };

    log::info!("Capture started. Press Ctrl+C to stop.");

    while running.load(Ordering::Relaxed) {
        if let Some(d) = duration_limit {
            if start.elapsed() >= d {
                log::info!("Duration reached, stopping capture");
                break;
            }
        }

        // Periodic status
        std::thread::sleep(Duration::from_secs(10));
        let total = writer.total_events();
        let elapsed = start.elapsed().as_secs();
        let rate = if elapsed > 0 { total / elapsed } else { 0 };
        log::info!("Events: {} ({}/s)", total, rate);
    }

    // Finalize
    log::info!("Finalizing capture...");
    let index_path = writer.finalize()?;
    log::info!("Run complete: {}", index_path.display());
    log::info!("Total events: {}", writer.total_events());

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This binary only works on Linux.");
    eprintln!("Please compile and run on a Linux system.");
    std::process::exit(1);
}
