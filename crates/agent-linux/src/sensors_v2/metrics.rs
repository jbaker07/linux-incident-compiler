//! Per-sensor performance metrics
pub struct SensorMetrics {
    pub sensor_name: String,
    pub last_ms: u128,
    pub max_5m_ms: u128,
    pub events_last: usize,
}

pub struct MetricsCollector {
    pub metrics: std::collections::BTreeMap<String, SensorMetrics>,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            metrics: std::collections::BTreeMap::new(),
        }
    }

    pub fn record(&mut self, sensor_name: &str, elapsed_ms: u128, event_count: usize) {
        self.metrics.insert(
            sensor_name.to_string(),
            SensorMetrics {
                sensor_name: sensor_name.to_string(),
                last_ms: elapsed_ms,
                max_5m_ms: elapsed_ms,
                events_last: event_count,
            },
        );
    }
}
