//! Unit tests for eBPF event decoder
//! Ensures: no panics, decode_failed increments correctly

#[cfg(test)]
mod ebpf_tests {
    use crate::ebpf::{EbpfEventStream, MockEbpfStream, RawEbpfEvent};

    #[test]
    fn test_decoder_no_panic_on_valid_events() {
        // Create valid event
        let evt = RawEbpfEvent {
            abi_version: 1,
            event_size: 384,
            ts: 1000,
            evt_type: 30,
            syscall_id: 59,
            tgid: 1234,
            ppid: 1000,
            uid: 1000,
            fd: -1,
            ret: 0,
            flags: 0,
            aux_u32: 0,
            aux_u64: 0,
            fam: 0,
            proto: 0,
            lport: 0,
            laddr4: 0,
            laddr6: [0; 16],
            rport: 0,
            raddr4: 0,
            raddr6: [0; 16],
            path: [0; 128],
            path2: [0; 128],
            comm: [0; 16],
        };

        // Serialize to bytes and feed to mock stream
        let mut bytes = [0u8; 384];
        bytes[0..4].copy_from_slice(&evt.abi_version.to_le_bytes());
        bytes[4..8].copy_from_slice(&evt.event_size.to_le_bytes());
        bytes[8..16].copy_from_slice(&evt.ts.to_le_bytes());
        bytes[16..20].copy_from_slice(&evt.evt_type.to_le_bytes());

        let mut stream = MockEbpfStream::from_bytes(bytes.to_vec());
        let result = stream.poll(100);
        assert!(result.is_ok(), "Decoder should not panic on valid events");
    }

    #[test]
    fn test_decoder_no_panic_on_invalid_abi() {
        // Create event with invalid ABI version
        let mut bytes = [0u8; 384];
        bytes[0..4].copy_from_slice(&99u32.to_le_bytes()); // Invalid ABI
        bytes[4..8].copy_from_slice(&384u32.to_le_bytes());

        let mut stream = MockEbpfStream::from_bytes(bytes.to_vec());
        let result = stream.poll(100);
        assert!(result.is_ok(), "Decoder should not panic on invalid ABI");
    }

    #[test]
    fn test_decoder_increments_decode_failed() {
        // Create event with wrong event_size
        let mut bytes = [0u8; 384];
        bytes[0..4].copy_from_slice(&1u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&256u32.to_le_bytes()); // Invalid size

        let mut stream = MockEbpfStream::from_bytes(bytes.to_vec());
        let _ = stream.poll(100);
        assert!(
            stream.loss_metrics().decode_errors > 0,
            "decode_failed should increment"
        );
    }

    #[test]
    fn test_decoder_no_panic_on_truncated() {
        // Truncated record
        let bytes = vec![0u8; 100]; // Less than 384

        let mut stream = MockEbpfStream::from_bytes(bytes);
        let result = stream.poll(100);
        assert!(result.is_ok(), "Decoder should not panic on truncated data");
    }

    #[test]
    fn test_decoder_handles_empty() {
        let bytes = vec![];
        let mut stream = MockEbpfStream::from_bytes(bytes);
        let result = stream.poll(100);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }
}
