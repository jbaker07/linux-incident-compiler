// crates/agent-linux/src/capture.rs
//
// Linux rotating capture - writes events to the run contract format:
//   index.json + segments/*.jsonl.gz

use crate::host::HostInfo;
use edr_core::Event;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Segment rotation configuration
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    /// Output directory for the run
    pub output_dir: PathBuf,
    /// Maximum events per segment
    pub events_per_segment: usize,
    /// Maximum segment duration in seconds
    pub segment_duration_secs: u64,
    /// Maximum segment size in bytes
    pub max_segment_bytes: usize,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            output_dir: PathBuf::from("./run"),
            events_per_segment: 100_000,
            segment_duration_secs: 300, // 5 minutes
            max_segment_bytes: 50 * 1024 * 1024, // 50 MB
        }
    }
}

/// Run index metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunIndex {
    pub version: String,
    pub run_id: String,
    pub start_time: i64,
    pub end_time: Option<i64>,
    pub host: HostInfo,
    pub segments: Vec<SegmentMeta>,
    pub total_events: u64,
    pub status: String,
}

/// Segment metadata in index
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentMeta {
    pub filename: String,
    pub start_time: i64,
    pub end_time: i64,
    pub event_count: u64,
    pub size_bytes: u64,
}

/// Active segment writer
struct ActiveSegment {
    path: PathBuf,
    writer: GzEncoder<BufWriter<File>>,
    start_time: i64,
    event_count: u64,
    bytes_written: usize,
}

/// Rotating capture writer
pub struct CaptureWriter {
    config: CaptureConfig,
    run_id: String,
    host: HostInfo,
    start_time: i64,
    segments_dir: PathBuf,
    current_segment: Option<ActiveSegment>,
    segment_index: usize,
    completed_segments: Vec<SegmentMeta>,
    total_events: AtomicU64,
}

impl CaptureWriter {
    /// Create a new capture writer
    pub fn new(config: CaptureConfig) -> std::io::Result<Self> {
        let run_id = uuid::Uuid::new_v4().to_string();
        let host = HostInfo::collect();
        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        // Create output directories
        fs::create_dir_all(&config.output_dir)?;
        let segments_dir = config.output_dir.join("segments");
        fs::create_dir_all(&segments_dir)?;

        Ok(Self {
            config,
            run_id,
            host,
            start_time,
            segments_dir,
            current_segment: None,
            segment_index: 0,
            completed_segments: Vec::new(),
            total_events: AtomicU64::new(0),
        })
    }

    /// Get current timestamp
    fn now_secs() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }

    /// Check if current segment needs rotation
    fn needs_rotation(&self) -> bool {
        match &self.current_segment {
            None => false,
            Some(seg) => {
                let age = Self::now_secs() - seg.start_time;
                seg.event_count >= self.config.events_per_segment as u64
                    || age >= self.config.segment_duration_secs as i64
                    || seg.bytes_written >= self.config.max_segment_bytes
            }
        }
    }

    /// Start a new segment
    fn start_segment(&mut self) -> std::io::Result<()> {
        let filename = format!("segment_{:06}.jsonl.gz", self.segment_index);
        let path = self.segments_dir.join(&filename);
        let file = File::create(&path)?;
        let writer = GzEncoder::new(BufWriter::new(file), Compression::default());

        self.current_segment = Some(ActiveSegment {
            path,
            writer,
            start_time: Self::now_secs(),
            event_count: 0,
            bytes_written: 0,
        });

        self.segment_index += 1;
        Ok(())
    }

    /// Finish current segment
    fn finish_segment(&mut self) -> std::io::Result<()> {
        if let Some(seg) = self.current_segment.take() {
            seg.writer.finish()?;

            let size_bytes = fs::metadata(&seg.path)
                .map(|m| m.len())
                .unwrap_or(0);

            let filename = seg.path
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();

            self.completed_segments.push(SegmentMeta {
                filename,
                start_time: seg.start_time,
                end_time: Self::now_secs(),
                event_count: seg.event_count,
                size_bytes,
            });
        }
        Ok(())
    }

    /// Rotate to a new segment
    fn rotate(&mut self) -> std::io::Result<()> {
        self.finish_segment()?;
        self.start_segment()?;
        Ok(())
    }

    /// Write an event
    pub fn write_event(&mut self, event: &Event) -> std::io::Result<()> {
        // Ensure we have an active segment
        if self.current_segment.is_none() {
            self.start_segment()?;
        }

        // Check for rotation
        if self.needs_rotation() {
            self.rotate()?;
        }

        // Serialize and write
        let json = serde_json::to_string(event)?;
        let bytes = json.as_bytes();

        if let Some(seg) = &mut self.current_segment {
            seg.writer.write_all(bytes)?;
            seg.writer.write_all(b"\n")?;
            seg.event_count += 1;
            seg.bytes_written += bytes.len() + 1;
        }

        self.total_events.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Finalize the run and write index.json
    pub fn finalize(&mut self) -> std::io::Result<PathBuf> {
        // Finish current segment
        self.finish_segment()?;

        // Write index.json
        let index = RunIndex {
            version: "1.0".to_string(),
            run_id: self.run_id.clone(),
            start_time: self.start_time,
            end_time: Some(Self::now_secs()),
            host: self.host.clone(),
            segments: self.completed_segments.clone(),
            total_events: self.total_events.load(Ordering::Relaxed),
            status: "complete".to_string(),
        };

        let index_path = self.config.output_dir.join("index.json");
        let file = File::create(&index_path)?;
        serde_json::to_writer_pretty(file, &index)?;

        Ok(index_path)
    }

    /// Get total events written
    pub fn total_events(&self) -> u64 {
        self.total_events.load(Ordering::Relaxed)
    }

    /// Get run ID
    pub fn run_id(&self) -> &str {
        &self.run_id
    }
}

/// Thread-safe capture writer wrapper
pub struct SharedCaptureWriter {
    inner: Arc<Mutex<CaptureWriter>>,
}

impl SharedCaptureWriter {
    pub fn new(config: CaptureConfig) -> std::io::Result<Self> {
        Ok(Self {
            inner: Arc::new(Mutex::new(CaptureWriter::new(config)?)),
        })
    }

    pub fn write_event(&self, event: &Event) -> std::io::Result<()> {
        let mut writer = self.inner.lock().unwrap();
        writer.write_event(event)
    }

    pub fn finalize(&self) -> std::io::Result<PathBuf> {
        let mut writer = self.inner.lock().unwrap();
        writer.finalize()
    }

    pub fn total_events(&self) -> u64 {
        let writer = self.inner.lock().unwrap();
        writer.total_events()
    }

    pub fn run_id(&self) -> String {
        let writer = self.inner.lock().unwrap();
        writer.run_id().to_string()
    }
}

impl Clone for SharedCaptureWriter {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_capture_writer() {
        let dir = tempdir().unwrap();
        let config = CaptureConfig {
            output_dir: dir.path().to_path_buf(),
            events_per_segment: 10,
            segment_duration_secs: 3600,
            max_segment_bytes: 10 * 1024 * 1024,
        };

        let mut writer = CaptureWriter::new(config).unwrap();

        // Write some events
        for i in 0..25 {
            let event = Event {
                ts_ms: 1234567890000 + i,
                host: "test-host".to_string(),
                tags: vec!["linux".to_string(), "test".to_string()],
                proc_key: Some(format!("test:{}", i)),
                file_key: None,
                identity_key: None,
                evidence_ptr: None,
                fields: Default::default(),
            };
            writer.write_event(&event).unwrap();
        }

        // Finalize
        let index_path = writer.finalize().unwrap();
        assert!(index_path.exists());

        // Read and verify index
        let index: RunIndex = serde_json::from_reader(File::open(&index_path).unwrap()).unwrap();
        assert_eq!(index.total_events, 25);
        assert!(index.segments.len() >= 2); // Should have rotated at least once
    }
}



