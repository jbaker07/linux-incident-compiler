/// Binary fixture generator for eBPF event testing
/// Creates .bin files with packed edr_event (384 bytes) records
use crate::ebpf::RawEbpfEvent;
use anyhow::Result;
use std::fs::File;
use std::io::Write;
use std::path::Path;

/// Serialize RawEbpfEvent to 384-byte binary format (little-endian)
fn event_to_bytes(event: &RawEbpfEvent) -> [u8; 384] {
    let mut bytes = [0u8; 384];

    // Header (abi_version, event_size)
    bytes[0..4].copy_from_slice(&event.abi_version.to_le_bytes());
    bytes[4..8].copy_from_slice(&event.event_size.to_le_bytes());

    // ts (u64)
    bytes[8..16].copy_from_slice(&event.ts.to_le_bytes());

    // u32 fields
    bytes[16..20].copy_from_slice(&event.evt_type.to_le_bytes());
    bytes[20..24].copy_from_slice(&event.syscall_id.to_le_bytes());
    bytes[24..28].copy_from_slice(&event.tgid.to_le_bytes());
    bytes[28..32].copy_from_slice(&event.ppid.to_le_bytes());
    bytes[32..36].copy_from_slice(&event.uid.to_le_bytes());

    // i32 fields
    bytes[36..40].copy_from_slice(&event.fd.to_le_bytes());
    bytes[40..44].copy_from_slice(&event.ret.to_le_bytes());

    // u32 fields
    bytes[44..48].copy_from_slice(&event.flags.to_le_bytes());
    bytes[48..52].copy_from_slice(&event.aux_u32.to_le_bytes());

    // u64 field
    bytes[52..60].copy_from_slice(&event.aux_u64.to_le_bytes());

    // u8/u16
    bytes[60] = event.fam;
    bytes[61] = event.proto;
    bytes[62..64].copy_from_slice(&event.lport.to_le_bytes());
    bytes[64..68].copy_from_slice(&event.laddr4.to_le_bytes());

    // IPv6
    bytes[68..84].copy_from_slice(&event.laddr6);
    bytes[84..86].copy_from_slice(&event.rport.to_le_bytes());
    bytes[86..90].copy_from_slice(&event.raddr4.to_le_bytes());
    bytes[90..106].copy_from_slice(&event.raddr6);

    // Strings
    bytes[106..234].copy_from_slice(&event.path);
    bytes[234..362].copy_from_slice(&event.path2);
    bytes[362..378].copy_from_slice(&event.comm);

    bytes
}

/// Generate valid + invalid mixed fixture (triggers decode_failed > 0)
pub fn gen_ebpf_events_bin<P: AsRef<Path>>(path: P) -> Result<usize> {
    let mut file = File::create(path)?;
    let mut count = 0;

    // Valid event 1: basic exec event
    let evt1 = RawEbpfEvent {
        abi_version: 1,
        event_size: 384,
        ts: 1000,
        evt_type: 30,   // EVT_EXEC
        syscall_id: 59, // execve
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
    file.write_all(&event_to_bytes(&evt1))?;
    count += 1;

    // Valid event 2: network connect
    let mut evt2 = RawEbpfEvent::default();
    evt2.abi_version = 1;
    evt2.event_size = 384;
    evt2.ts = 2000;
    evt2.evt_type = 200; // EVT_TCP_CONNECT
    evt2.syscall_id = 42; // connect
    evt2.tgid = 1234;
    evt2.fam = 2; // AF_INET
    evt2.proto = 6; // IPPROTO_TCP
    evt2.lport = 1024u16.to_be();
    evt2.rport = 443u16.to_be();
    file.write_all(&event_to_bytes(&evt2))?;
    count += 1;

    // Invalid event 1: wrong abi_version
    let mut evt_bad_abi = RawEbpfEvent::default();
    evt_bad_abi.abi_version = 99; // WRONG!
    evt_bad_abi.event_size = 384;
    file.write_all(&event_to_bytes(&evt_bad_abi))?;
    count += 1;

    // Invalid event 2: wrong event_size
    let mut evt_bad_size = RawEbpfEvent::default();
    evt_bad_size.abi_version = 1;
    evt_bad_size.event_size = 256; // WRONG!
    file.write_all(&event_to_bytes(&evt_bad_size))?;
    count += 1;

    // Valid event 3: file operation
    let mut evt3 = RawEbpfEvent::default();
    evt3.abi_version = 1;
    evt3.event_size = 384;
    evt3.ts = 3000;
    evt3.evt_type = 10; // EVT_OPEN
    evt3.syscall_id = 257; // openat
    evt3.tgid = 1234;
    evt3.ret = 5; // fd 5
    file.write_all(&event_to_bytes(&evt3))?;
    count += 1;

    // Truncated record (not enough bytes to fill event)
    file.write_all(&[0u8; 100])?;

    Ok(count)
}

/// Generate only valid events (smoke test)
pub fn gen_valid_ebpf_events_bin<P: AsRef<Path>>(path: P) -> Result<usize> {
    let mut file = File::create(path)?;

    for i in 0..5 {
        let evt = RawEbpfEvent {
            abi_version: 1,
            event_size: 384,
            ts: 1000 + (i as u64 * 1000),
            evt_type: (30 + i) as u32, // Vary event type
            syscall_id: (59 + i) as u32,
            tgid: 1000 + i as u32,
            ppid: 500 + i as u32,
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

        file.write_all(&event_to_bytes(&evt))?;
    }

    Ok(5)
}

// Tests can be added once tempfile is available as test dependency
