//! OS-specific signal detection engines and fact extractors
//!
//! Each OS module provides:
//! - Signal engine for real-time detection
//! - Fact extractor for converting raw events to canonical facts
//! - Tag enrichment for telemetry source mapping

pub mod linux;
pub mod macos;
pub mod windows;

// Re-export key types for convenience
pub use linux::{extract_facts as extract_linux_facts, LinuxSignalEngine};
pub use windows::{extract_facts as extract_windows_facts, WindowsSignalEngine};
