//! DNS Event Capture for Linux
//!
//! Provides DNS query telemetry by parsing:
//! 1. systemd-resolved journal logs (preferred)
//! 2. dnsmasq logs (fallback)
//! 3. /var/log/syslog DNS patterns (last resort)
//!
//! Output: DnsResolve facts for playbook matching (C2 detection, DNS tunneling)

use crate::canonical::fact::{Fact, FactType, FieldValue};
use crate::evidence::EvidencePtr;
use edr_core::Event;
use regex::Regex;
use std::collections::HashMap;

/// DNS query types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsQueryType {
    A,
    AAAA,
    CNAME,
    MX,
    TXT,
    NS,
    SOA,
    PTR,
    SRV,
    Unknown,
}

impl DnsQueryType {
    pub fn from_u16(v: u16) -> Self {
        match v {
            1 => Self::A,
            28 => Self::AAAA,
            5 => Self::CNAME,
            15 => Self::MX,
            16 => Self::TXT,
            2 => Self::NS,
            6 => Self::SOA,
            12 => Self::PTR,
            33 => Self::SRV,
            _ => Self::Unknown,
        }
    }

    pub fn parse(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "A" => Self::A,
            "AAAA" => Self::AAAA,
            "CNAME" => Self::CNAME,
            "MX" => Self::MX,
            "TXT" => Self::TXT,
            "NS" => Self::NS,
            "SOA" => Self::SOA,
            "PTR" => Self::PTR,
            "SRV" => Self::SRV,
            _ => Self::Unknown,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::A => "A",
            Self::AAAA => "AAAA",
            Self::CNAME => "CNAME",
            Self::MX => "MX",
            Self::TXT => "TXT",
            Self::NS => "NS",
            Self::SOA => "SOA",
            Self::PTR => "PTR",
            Self::SRV => "SRV",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// Parsed DNS query from logs
#[derive(Debug, Clone)]
pub struct DnsQuery {
    pub query_name: String,
    pub query_type: DnsQueryType,
    pub resolved_ips: Vec<String>,
    pub proc_key: Option<String>,
    pub pid: Option<u32>,
    pub ts_ms: i64,
}

lazy_static::lazy_static! {
    // systemd-resolved: "Resolving example.com IN A" or "Resolved example.com IN A: 93.184.216.34"
    static ref RESOLVED_QUERY_RE: Regex = Regex::new(
        r"(?i)Resolv(?:ing|ed)\s+(\S+)\s+IN\s+(\w+)(?::\s*(.+))?"
    ).unwrap();

    // dnsmasq: "query[A] example.com from 127.0.0.1"
    static ref DNSMASQ_QUERY_RE: Regex = Regex::new(
        r"(?i)query\[(\w+)\]\s+(\S+)\s+from\s+(\S+)"
    ).unwrap();

    // dnsmasq reply: "reply example.com is 93.184.216.34"
    static ref DNSMASQ_REPLY_RE: Regex = Regex::new(
        r"(?i)reply\s+(\S+)\s+is\s+(.+)"
    ).unwrap();

    // Generic syslog DNS: "DNS query: example.com"
    static ref GENERIC_DNS_RE: Regex = Regex::new(
        r"(?i)DNS\s+(?:query|lookup|resolve)[:\s]+(\S+)"
    ).unwrap();
}

/// Check if event is a DNS-related event
pub fn is_dns_event(event: &Event) -> bool {
    // Check tags
    if event
        .tags
        .iter()
        .any(|t| t == "dns" || t == "dns_query" || t == "resolved" || t == "dnsmasq")
    {
        return true;
    }

    // Check systemd unit
    if let Some(unit) = event.fields.get("_SYSTEMD_UNIT").and_then(|v| v.as_str()) {
        if unit.contains("resolved") || unit.contains("dnsmasq") {
            return true;
        }
    }

    // Check message for DNS patterns
    if let Some(msg) = event
        .fields
        .get("MESSAGE")
        .or_else(|| event.fields.get("message"))
        .and_then(|v| v.as_str())
    {
        let msg_lower = msg.to_lowercase();
        if msg_lower.contains("dns") || msg_lower.contains("resolv") || msg_lower.contains("query[")
        {
            return true;
        }
    }

    false
}

/// Parse DNS query from event
pub fn parse_dns_event(event: &Event) -> Option<DnsQuery> {
    let msg = event
        .fields
        .get("MESSAGE")
        .or_else(|| event.fields.get("message"))
        .and_then(|v| v.as_str())?;

    // Try systemd-resolved format
    if let Some(caps) = RESOLVED_QUERY_RE.captures(msg) {
        let query_name = caps.get(1)?.as_str().to_string();
        let qtype = DnsQueryType::parse(caps.get(2)?.as_str());
        let resolved_ips = caps
            .get(3)
            .map(|m| parse_ip_list(m.as_str()))
            .unwrap_or_default();

        return Some(DnsQuery {
            query_name,
            query_type: qtype,
            resolved_ips,
            proc_key: event.proc_key.clone(),
            pid: event
                .fields
                .get("_PID")
                .and_then(|v| v.as_u64())
                .map(|p| p as u32),
            ts_ms: event.ts_ms,
        });
    }

    // Try dnsmasq query format
    if let Some(caps) = DNSMASQ_QUERY_RE.captures(msg) {
        let qtype = DnsQueryType::parse(caps.get(1)?.as_str());
        let query_name = caps.get(2)?.as_str().to_string();

        return Some(DnsQuery {
            query_name,
            query_type: qtype,
            resolved_ips: Vec::new(), // Will be filled by reply
            proc_key: event.proc_key.clone(),
            pid: event
                .fields
                .get("_PID")
                .and_then(|v| v.as_u64())
                .map(|p| p as u32),
            ts_ms: event.ts_ms,
        });
    }

    // Try generic pattern
    if let Some(caps) = GENERIC_DNS_RE.captures(msg) {
        let query_name = caps.get(1)?.as_str().to_string();

        return Some(DnsQuery {
            query_name,
            query_type: DnsQueryType::A, // Assume A record
            resolved_ips: Vec::new(),
            proc_key: event.proc_key.clone(),
            pid: event
                .fields
                .get("_PID")
                .and_then(|v| v.as_u64())
                .map(|p| p as u32),
            ts_ms: event.ts_ms,
        });
    }

    // Check if fields directly contain DNS data
    if let Some(query) = event
        .fields
        .get("query")
        .or_else(|| event.fields.get("dns.query"))
        .and_then(|v| v.as_str())
    {
        let qtype = event
            .fields
            .get("qtype")
            .or_else(|| event.fields.get("dns.type"))
            .and_then(|v| v.as_str())
            .map(DnsQueryType::parse)
            .unwrap_or(DnsQueryType::A);

        let resolved_ips = event
            .fields
            .get("answers")
            .or_else(|| event.fields.get("dns.answers"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        return Some(DnsQuery {
            query_name: query.to_string(),
            query_type: qtype,
            resolved_ips,
            proc_key: event.proc_key.clone(),
            pid: event
                .fields
                .get("pid")
                .and_then(|v| v.as_u64())
                .map(|p| p as u32),
            ts_ms: event.ts_ms,
        });
    }

    None
}

/// Parse IP addresses from a comma/space separated string
fn parse_ip_list(s: &str) -> Vec<String> {
    s.split([',', ' '])
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && (s.contains('.') || s.contains(':')))
        .map(|s| s.to_string())
        .collect()
}

/// Extract DNS fact from event
pub fn extract_dns_fact(event: &Event, host_id: &str, evidence: &EvidencePtr) -> Option<Fact> {
    let query = parse_dns_event(event)?;

    let proc_key = query
        .proc_key
        .or_else(|| query.pid.map(|p| format!("proc_{}_{}", host_id, p)))
        .unwrap_or_else(|| format!("proc_{}_{}", host_id, 0));

    let scope_key = format!("dns:{}", query.query_name);

    let fact_type = FactType::DnsResolve {
        proc_key: proc_key.clone(),
        query_name: query.query_name.clone(),
        resolved_ips: query.resolved_ips.clone(),
    };

    let fact_id = Fact::compute_fact_id(host_id, &scope_key, &fact_type, event.ts_ms);

    let mut fields = HashMap::new();
    fields.insert(
        "query_type".to_string(),
        FieldValue::string(query.query_type.as_str()),
    );

    Some(Fact {
        fact_id,
        ts: event.ts_ms,
        host_id: host_id.to_string(),
        scope_key,
        fact_type,
        fields,
        evidence_ptrs: vec![evidence.clone()],
        conflict_set_id: None,
        visibility_gaps: Vec::new(),
    })
}

/// DNS tunneling detection heuristics
pub struct DnsTunnelingDetector {
    /// Track query volume per domain
    domain_query_count: HashMap<String, u32>,
    /// Track long subdomains
    long_subdomain_threshold: usize,
}

impl Default for DnsTunnelingDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsTunnelingDetector {
    pub fn new() -> Self {
        Self {
            domain_query_count: HashMap::new(),
            long_subdomain_threshold: 50,
        }
    }

    /// Check if query looks like DNS tunneling
    pub fn is_suspicious(&mut self, query: &DnsQuery) -> bool {
        let domain = &query.query_name;

        // Long subdomain labels (base64 encoded data)
        if domain.len() > self.long_subdomain_threshold {
            return true;
        }

        // High entropy domain labels
        if Self::has_high_entropy_label(domain) {
            return true;
        }

        // TXT queries to unusual domains
        if query.query_type == DnsQueryType::TXT {
            let base_domain = Self::extract_base_domain(domain);
            *self
                .domain_query_count
                .entry(base_domain.clone())
                .or_insert(0) += 1;
            if self.domain_query_count.get(&base_domain).unwrap_or(&0) > &10 {
                return true;
            }
        }

        false
    }

    fn has_high_entropy_label(domain: &str) -> bool {
        // Check if any label looks like base64/hex
        for label in domain.split('.') {
            if label.len() > 20 {
                let alpha_count = label.chars().filter(|c| c.is_alphabetic()).count();
                let digit_count = label.chars().filter(|c| c.is_numeric()).count();
                // High mix of letters and numbers suggests encoding
                if alpha_count > 5 && digit_count > 5 {
                    return true;
                }
            }
        }
        false
    }

    fn extract_base_domain(domain: &str) -> String {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() >= 2 {
            parts[parts.len() - 2..].join(".")
        } else {
            domain.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_resolved_query() {
        let mut fields = std::collections::BTreeMap::new();
        fields.insert(
            "MESSAGE".to_string(),
            serde_json::json!("Resolved example.com IN A: 93.184.216.34"),
        );

        let event = Event {
            ts_ms: 1704672000000,
            host: "test".to_string(),
            tags: vec!["resolved".to_string()],
            proc_key: Some("proc_1".to_string()),
            file_key: None,
            identity_key: None,
            evidence_ptr: None,
            fields,
        };

        let query = parse_dns_event(&event).unwrap();
        assert_eq!(query.query_name, "example.com");
        assert_eq!(query.query_type, DnsQueryType::A);
        assert_eq!(query.resolved_ips, vec!["93.184.216.34"]);
    }

    #[test]
    fn test_parse_dnsmasq_query() {
        let mut fields = std::collections::BTreeMap::new();
        fields.insert(
            "MESSAGE".to_string(),
            serde_json::json!("query[A] evil.com from 127.0.0.1"),
        );

        let event = Event {
            ts_ms: 1704672000000,
            host: "test".to_string(),
            tags: vec!["dnsmasq".to_string()],
            proc_key: None,
            file_key: None,
            identity_key: None,
            evidence_ptr: None,
            fields,
        };

        let query = parse_dns_event(&event).unwrap();
        assert_eq!(query.query_name, "evil.com");
        assert_eq!(query.query_type, DnsQueryType::A);
    }

    #[test]
    fn test_dns_tunneling_detection() {
        let mut detector = DnsTunnelingDetector::new();

        // Normal query
        let normal = DnsQuery {
            query_name: "example.com".to_string(),
            query_type: DnsQueryType::A,
            resolved_ips: vec![],
            proc_key: None,
            pid: None,
            ts_ms: 0,
        };
        assert!(!detector.is_suspicious(&normal));

        // Long subdomain (tunneling indicator)
        let tunneling = DnsQuery {
            query_name: "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHZlcnkgbG9uZyBlbmNvZGVkIG1lc3NhZ2U.evil.com"
                .to_string(),
            query_type: DnsQueryType::TXT,
            resolved_ips: vec![],
            proc_key: None,
            pid: None,
            ts_ms: 0,
        };
        assert!(detector.is_suspicious(&tunneling));
    }

    #[test]
    fn test_query_type_parsing() {
        assert_eq!(DnsQueryType::parse("A"), DnsQueryType::A);
        assert_eq!(DnsQueryType::parse("AAAA"), DnsQueryType::AAAA);
        assert_eq!(DnsQueryType::parse("TXT"), DnsQueryType::TXT);
        assert_eq!(DnsQueryType::parse("txt"), DnsQueryType::TXT);
    }
}
