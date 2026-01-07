/// MockEbpfStream reads binary fixture of packed edr_event records
/// Used for testing without actual kernel attachment
use crate::ebpf::{EbpfEventStream, LossMetrics, RawEbpfEvent, TransportKind};
use anyhow::Result;
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Mock eBPF stream reading from binary fixture file
pub struct MockEbpfStream {
    reader: Box<dyn Read>,
    buffer: Vec<u8>,
    transport_kind: TransportKind,
    events_read_total: u64,
    loss_metrics: LossMetrics,
}

impl MockEbpfStream {
    /// Create from binary fixture file
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path)?;
        Ok(Self {
            reader: Box::new(file),
            buffer: vec![0u8; 384 * 1000], // Enough for ~1000 events per read
            transport_kind: TransportKind::None,
            events_read_total: 0,
            loss_metrics: LossMetrics::default(),
        })
    }

    /// Create from in-memory bytes (for testing)
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            reader: Box::new(std::io::Cursor::new(bytes)),
            buffer: vec![0u8; 384 * 1000],
            transport_kind: TransportKind::None,
            events_read_total: 0,
            loss_metrics: LossMetrics::default(),
        }
    }
}

impl EbpfEventStream for MockEbpfStream {
    fn poll(&mut self, _timeout_ms: i32) -> Result<Vec<RawEbpfEvent>> {
        // Read up to 100 events (384 bytes each) from fixture
        let read_size = (100 * 384).min(self.buffer.len());
        let n = self.reader.read(&mut self.buffer[..read_size]).unwrap_or(0);

        let mut events = Vec::new();
        let mut decode_failed = 0;

        // Parse each 384-byte record
        for chunk in self.buffer[..n].chunks_exact_mut(384) {
            // SAFETY: We know chunk is exactly 384 bytes
            let event_bytes = &chunk[..];

            // Check minimum size for header fields
            if event_bytes.len() < 12 {
                decode_failed += 1;
                continue;
            }

            // Parse ABI version and size (little-endian u32)
            let abi_version = u32::from_le_bytes([
                event_bytes[0],
                event_bytes[1],
                event_bytes[2],
                event_bytes[3],
            ]);
            let event_size = u32::from_le_bytes([
                event_bytes[4],
                event_bytes[5],
                event_bytes[6],
                event_bytes[7],
            ]);

            // Validate ABI
            if abi_version != 1 || event_size != 384 {
                decode_failed += 1;
                self.loss_metrics.decode_errors += 1;
                continue;
            }

            // Parse the rest of the event
            match parse_raw_event_bytes(event_bytes) {
                Ok(evt) => {
                    events.push(evt);
                    self.events_read_total += 1;
                }
                Err(_) => {
                    decode_failed += 1;
                    self.loss_metrics.decode_errors += 1;
                }
            }
        }

        Ok(events)
    }

    fn transport_kind(&self) -> TransportKind {
        TransportKind::None
    }

    fn loss_metrics(&self) -> LossMetrics {
        self.loss_metrics
    }

    fn events_read_total(&self) -> u64 {
        self.events_read_total
    }
}

/// Parse 384-byte record into RawEbpfEvent
fn parse_raw_event_bytes(bytes: &[u8]) -> Result<RawEbpfEvent> {
    if bytes.len() < 384 {
        return Err(anyhow::anyhow!("Event too short: {} bytes", bytes.len()));
    }

    let mut event = RawEbpfEvent::default();

    // Header
    event.abi_version = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    event.event_size = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

    // Core fields (u64 alignment)
    event.ts = u64::from_le_bytes([
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ]);

    // u32 fields (offset 16+)
    event.evt_type = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
    event.syscall_id = u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
    event.tgid = u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]);
    event.ppid = u32::from_le_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]);
    event.uid = u32::from_le_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]);

    // i32 fields
    event.fd = i32::from_le_bytes([bytes[36], bytes[37], bytes[38], bytes[39]]);
    event.ret = i32::from_le_bytes([bytes[40], bytes[41], bytes[42], bytes[43]]);

    // u32 fields
    event.flags = u32::from_le_bytes([bytes[44], bytes[45], bytes[46], bytes[47]]);
    event.aux_u32 = u32::from_le_bytes([bytes[48], bytes[49], bytes[50], bytes[51]]);

    // u64 field
    event.aux_u64 = u64::from_le_bytes([
        bytes[52], bytes[53], bytes[54], bytes[55], bytes[56], bytes[57], bytes[58], bytes[59],
    ]);

    // u8/u16 fields
    event.fam = bytes[60];
    event.proto = bytes[61];
    event.lport = u16::from_le_bytes([bytes[62], bytes[63]]);
    event.laddr4 = u32::from_le_bytes([bytes[64], bytes[65], bytes[66], bytes[67]]);

    // IPv6 addresses
    event.laddr6.copy_from_slice(&bytes[68..84]);
    event.rport = u16::from_le_bytes([bytes[84], bytes[85]]);
    event.raddr4 = u32::from_le_bytes([bytes[86], bytes[87], bytes[88], bytes[89]]);
    event.raddr6.copy_from_slice(&bytes[90..106]);

    // Strings
    event.path.copy_from_slice(&bytes[106..234]);
    event.path2.copy_from_slice(&bytes[234..362]);
    event.comm.copy_from_slice(&bytes[362..378]);

    Ok(event)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_stream_empty() {
        let bytes = vec![];
        let mut stream = MockEbpfStream::from_bytes(bytes);
        let events = stream.poll(100).unwrap();
        assert_eq!(events.len(), 0);
    }

    #[test]
    fn test_mock_stream_truncated() {
        let bytes = vec![0u8; 100]; // Less than 384
        let mut stream = MockEbpfStream::from_bytes(bytes);
        let events = stream.poll(100).unwrap();
        assert_eq!(events.len(), 0);
        assert_eq!(stream.loss_metrics().decode_errors, 0); // Not a full record
    }
}
