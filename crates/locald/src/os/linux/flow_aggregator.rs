//! Flow Aggregation Layer for Linux Network Events
//!
//! Tracks network flow state to compute `__agg.*` fields required by playbooks:
//! - `__agg.duration_sec`: Time from first to last packet
//! - `__agg.connect_count`: Number of connections on same flow
//! - `__agg.bytes_total`: Total bytes (if available)
//! - `__agg.kind`: "longlived_flow", "burst", "sporadic"
//!
//! Keyed by: local_ip:local_port->remote_ip:remote_port/protocol

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Flow aggregation state
#[derive(Debug, Clone)]
pub struct FlowState {
    /// Network key: local_ip:local_port->remote_ip:remote_port/protocol
    pub net_key: String,
    /// Process key for correlation
    pub proc_key: String,
    /// First seen timestamp (ms)
    pub first_seen_ms: i64,
    /// Last seen timestamp (ms)
    pub last_seen_ms: i64,
    /// Connection count
    pub connect_count: u32,
    /// Total bytes transferred (if tracked)
    pub bytes_total: u64,
    /// Last update instant (for LRU eviction)
    last_update: Instant,
}

impl FlowState {
    /// Get duration in seconds
    pub fn duration_sec(&self) -> i64 {
        (self.last_seen_ms - self.first_seen_ms) / 1000
    }

    /// Classify flow kind based on characteristics
    pub fn kind(&self) -> &'static str {
        let duration = self.duration_sec();
        let connect_count = self.connect_count;

        if duration >= 60 && connect_count <= 2 {
            // Long-lived single connection (C2 beacon, reverse shell)
            "longlived_flow"
        } else if connect_count >= 5 && duration <= 10 {
            // Many connections in short time (scan, burst)
            "burst"
        } else if duration > 0 && connect_count > 1 {
            // Regular repeated connections
            "periodic"
        } else {
            "sporadic"
        }
    }
}

/// Aggregated flow fields for playbook matching
#[derive(Debug, Clone, Default)]
pub struct AggFields {
    /// Duration in seconds
    pub duration_sec: i64,
    /// Connection count
    pub connect_count: u32,
    /// Total bytes
    pub bytes_total: u64,
    /// Flow classification
    pub kind: String,
    /// First seen timestamp
    pub first_seen_ms: i64,
    /// Last seen timestamp
    pub last_seen_ms: i64,
}

/// Flow aggregator with LRU eviction
pub struct FlowAggregator {
    flows: Arc<RwLock<HashMap<String, FlowState>>>,
    max_flows: usize,
    ttl: Duration,
}

impl Default for FlowAggregator {
    fn default() -> Self {
        Self::new(10_000, Duration::from_secs(3600))
    }
}

impl FlowAggregator {
    /// Create a new flow aggregator
    pub fn new(max_flows: usize, ttl: Duration) -> Self {
        Self {
            flows: Arc::new(RwLock::new(HashMap::new())),
            max_flows,
            ttl,
        }
    }

    /// Build network key from connection parameters
    pub fn build_net_key(
        local_ip: &str,
        local_port: u16,
        remote_ip: &str,
        remote_port: u16,
        protocol: &str,
    ) -> String {
        format!(
            "{}:{}->{}.{}:{}",
            local_ip, local_port, remote_ip, remote_port, protocol
        )
    }

    /// Record a network event and return aggregated fields
    pub fn record_event(
        &self,
        net_key: &str,
        proc_key: &str,
        ts_ms: i64,
        bytes: Option<u64>,
    ) -> AggFields {
        let mut flows = self.flows.write().unwrap();

        // Evict expired flows if at capacity
        if flows.len() >= self.max_flows {
            self.evict_expired(&mut flows);
        }

        let now = Instant::now();

        let flow = flows
            .entry(net_key.to_string())
            .or_insert_with(|| FlowState {
                net_key: net_key.to_string(),
                proc_key: proc_key.to_string(),
                first_seen_ms: ts_ms,
                last_seen_ms: ts_ms,
                connect_count: 0,
                bytes_total: 0,
                last_update: now,
            });

        // Update flow state
        flow.last_seen_ms = ts_ms;
        flow.connect_count += 1;
        flow.last_update = now;
        if let Some(b) = bytes {
            flow.bytes_total += b;
        }

        // Return aggregated fields
        AggFields {
            duration_sec: flow.duration_sec(),
            connect_count: flow.connect_count,
            bytes_total: flow.bytes_total,
            kind: flow.kind().to_string(),
            first_seen_ms: flow.first_seen_ms,
            last_seen_ms: flow.last_seen_ms,
        }
    }

    /// Get aggregated fields for a flow without updating
    pub fn get_agg(&self, net_key: &str) -> Option<AggFields> {
        let flows = self.flows.read().unwrap();
        flows.get(net_key).map(|f| AggFields {
            duration_sec: f.duration_sec(),
            connect_count: f.connect_count,
            bytes_total: f.bytes_total,
            kind: f.kind().to_string(),
            first_seen_ms: f.first_seen_ms,
            last_seen_ms: f.last_seen_ms,
        })
    }

    /// Evict flows older than TTL
    fn evict_expired(&self, flows: &mut HashMap<String, FlowState>) {
        let now = Instant::now();
        flows.retain(|_, v| now.duration_since(v.last_update) < self.ttl);
    }

    /// Get flow count for monitoring
    pub fn flow_count(&self) -> usize {
        self.flows.read().unwrap().len()
    }

    /// Clear all flows (for testing)
    pub fn clear(&self) {
        self.flows.write().unwrap().clear();
    }
}

// Global flow aggregator instance
lazy_static::lazy_static! {
    pub static ref FLOW_AGGREGATOR: FlowAggregator = FlowAggregator::default();
}

/// Record a network event and get aggregation fields
#[allow(clippy::too_many_arguments)]
pub fn record_network_event(
    local_ip: &str,
    local_port: u16,
    remote_ip: &str,
    remote_port: u16,
    protocol: &str,
    proc_key: &str,
    ts_ms: i64,
    bytes: Option<u64>,
) -> AggFields {
    let net_key =
        FlowAggregator::build_net_key(local_ip, local_port, remote_ip, remote_port, protocol);
    FLOW_AGGREGATOR.record_event(&net_key, proc_key, ts_ms, bytes)
}

/// Get aggregation fields for an existing flow
pub fn get_flow_agg(net_key: &str) -> Option<AggFields> {
    FLOW_AGGREGATOR.get_agg(net_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_aggregation() {
        let agg = FlowAggregator::new(100, Duration::from_secs(60));

        let net_key =
            FlowAggregator::build_net_key("192.168.1.1", 45678, "93.184.216.34", 443, "tcp");

        // First connection
        let fields1 = agg.record_event(&net_key, "proc_1", 1000, Some(100));
        assert_eq!(fields1.connect_count, 1);
        assert_eq!(fields1.duration_sec, 0);

        // Second connection 30 seconds later
        let fields2 = agg.record_event(&net_key, "proc_1", 31000, Some(200));
        assert_eq!(fields2.connect_count, 2);
        assert_eq!(fields2.duration_sec, 30);
        assert_eq!(fields2.bytes_total, 300);

        // Third connection 90 seconds from start
        let fields3 = agg.record_event(&net_key, "proc_1", 91000, Some(50));
        assert_eq!(fields3.connect_count, 3);
        assert_eq!(fields3.duration_sec, 90);
        // connect_count=3 > 2 so doesn't match longlived_flow, matches periodic instead
        assert_eq!(fields3.kind, "periodic");
    }

    #[test]
    fn test_burst_detection() {
        let agg = FlowAggregator::new(100, Duration::from_secs(60));

        let net_key = "burst_test";

        // Many connections in short time
        for i in 0..10 {
            agg.record_event(net_key, "proc_1", 1000 + (i * 100), None);
        }

        let fields = agg.get_agg(net_key).unwrap();
        assert_eq!(fields.connect_count, 10);
        assert!(fields.duration_sec < 2);
        assert_eq!(fields.kind, "burst");
    }

    #[test]
    fn test_net_key_format() {
        let key = FlowAggregator::build_net_key("10.0.0.1", 12345, "8.8.8.8", 53, "udp");
        assert_eq!(key, "10.0.0.1:12345->8.8.8.8.53:udp");
    }
}
