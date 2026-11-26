//! Detection logic: turns decoded packets into alerts.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::net::IpAddr;

use serde::Serialize;

use crate::alert::{Alert, Severity};
use crate::decode::{decode, Decoded, Transport, TCP_ACK, TCP_SYN};
use crate::dns::{self, shannon_entropy, DnsMessage};
use crate::pcap::{Packet, PcapError, PcapReader};
use crate::rules::Rules;

/// Counters of one analysis run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Stats {
    pub packets: usize,
    pub decoded: usize,
    pub dns_queries: usize,
    pub alerts: usize,
}

/// Tumbling counting window per key.
struct Window {
    start: f64,
    count: u32,
    alerted: bool,
}

impl Window {
    fn new(start: f64) -> Self {
        Self {
            start,
            count: 0,
            alerted: false,
        }
    }
}

struct PortWindow {
    start: f64,
    ports: HashSet<u16>,
    alerted: bool,
}

impl PortWindow {
    fn new(start: f64) -> Self {
        Self {
            start,
            ports: HashSet::new(),
            alerted: false,
        }
    }
}

/// Counts one event for `ip`; true exactly once per window when the threshold is reached.
fn bump(
    map: &mut HashMap<IpAddr, Window>,
    ip: IpAddr,
    ts: f64,
    window_secs: f64,
    threshold: u32,
) -> bool {
    let entry = map.entry(ip).or_insert_with(|| Window::new(ts));
    if ts - entry.start > window_secs {
        *entry = Window::new(ts);
    }
    entry.count += 1;
    if entry.alerted || entry.count < threshold {
        return false;
    }
    entry.alerted = true;
    true
}

fn alert(rule: &str, sev: Severity, ts: f64, d: &Decoded<'_>, msg: &str) -> Alert {
    Alert::new(rule, sev, ts, d.src, d.dst, msg)
}

fn has_random_label(name: &str, min_len: usize, threshold: f64) -> bool {
    for label in name.split('.') {
        if label.len() >= min_len && shannon_entropy(label) >= threshold {
            return true;
        }
    }
    false
}

/// Stateful analyzer; feed packets in capture order.
pub struct Analyzer {
    rules: Rules,
    stats: Stats,
    seen_ports: HashSet<(IpAddr, IpAddr, u16)>,
    dns_bursts: HashMap<IpAddr, Window>,
    nx_bursts: HashMap<IpAddr, Window>,
    scans: HashMap<(IpAddr, IpAddr), PortWindow>,
    seen_dns: HashSet<(String, &'static str)>,
}

impl Analyzer {
    pub fn new(rules: Rules) -> Self {
        Self {
            rules,
            stats: Stats::default(),
            seen_ports: HashSet::new(),
            dns_bursts: HashMap::new(),
            nx_bursts: HashMap::new(),
            scans: HashMap::new(),
            seen_dns: HashSet::new(),
        }
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// Analyzes one captured packet and returns the alerts it triggered.
    pub fn packet(&mut self, link_type: u32, packet: &Packet) -> Vec<Alert> {
        self.stats.packets += 1;
        match decode(link_type, &packet.data) {
            Some(decoded) => self.process(packet.timestamp, &decoded),
            None => Vec::new(),
        }
    }

    fn process(&mut self, ts: f64, d: &Decoded<'_>) -> Vec<Alert> {
        self.stats.decoded += 1;
        let mut alerts = Vec::new();
        alerts.extend(self.check_port(ts, d));
        alerts.extend(self.check_scan(ts, d));
        let is_dns = d.transport == Transport::Udp && (d.dst_port == 53 || d.src_port == 53);
        if is_dns {
            alerts.extend(self.check_dns(ts, d));
        }
        self.stats.alerts += alerts.len();
        alerts
    }

    fn check_port(&mut self, ts: f64, d: &Decoded<'_>) -> Option<Alert> {
        let initiating = match d.transport {
            Transport::Tcp { flags } => (flags & TCP_SYN) != 0 && (flags & TCP_ACK) == 0,
            Transport::Udp => true,
        };
        if !initiating || !self.rules.suspicious_ports.contains(&d.dst_port) {
            return None;
        }
        if !self.seen_ports.insert((d.src, d.dst, d.dst_port)) {
            return None;
        }
        let message = format!("traffic to suspicious port {}", d.dst_port);
        Some(alert("suspicious-port", Severity::Medium, ts, d, &message))
    }

    fn check_scan(&mut self, ts: f64, d: &Decoded<'_>) -> Option<Alert> {
        let Transport::Tcp { flags } = d.transport else {
            return None;
        };
        if (flags & TCP_SYN) == 0 || (flags & TCP_ACK) != 0 {
            return None;
        }
        let window = self.rules.window_secs;
        let threshold = self.rules.port_scan_threshold as usize;
        let scans = &mut self.scans;
        let entry = scans
            .entry((d.src, d.dst))
            .or_insert_with(|| PortWindow::new(ts));
        if ts - entry.start > window {
            *entry = PortWindow::new(ts);
        }
        entry.ports.insert(d.dst_port);
        if entry.alerted || entry.ports.len() < threshold {
            return None;
        }
        entry.alerted = true;
        let message = format!("{} distinct ports probed", entry.ports.len());
        Some(alert("port-scan", Severity::High, ts, d, &message))
    }

    fn check_dns(&mut self, ts: f64, d: &Decoded<'_>) -> Vec<Alert> {
        let Some(msg) = dns::parse(d.payload) else {
            return Vec::new();
        };
        let window = self.rules.window_secs;
        let mut alerts = Vec::new();
        if msg.is_response {
            if msg.rcode == 3 {
                let threshold = self.rules.nxdomain_threshold;
                if bump(&mut self.nx_bursts, d.dst, ts, window, threshold) {
                    let text = "many NXDOMAIN answers (possible DGA activity)";
                    alerts.push(alert("dns-nxdomain-burst", Severity::High, ts, d, text));
                }
            }
            return alerts;
        }
        self.stats.dns_queries += 1;
        alerts.extend(self.dns_name_alerts(ts, d, &msg));
        let threshold = self.rules.dns_burst_threshold;
        if bump(&mut self.dns_bursts, d.src, ts, window, threshold) {
            let text = "burst of DNS queries from one host";
            alerts.push(alert("dns-query-burst", Severity::Medium, ts, d, text));
        }
        alerts
    }

    fn first_time(&mut self, name: &str, rule: &'static str) -> bool {
        self.seen_dns.insert((name.to_string(), rule))
    }

    /// Query name as shown in alerts: long first labels are cut to four characters.
    fn display_name(&self, name: &str) -> String {
        if !self.rules.mask_names {
            return name.to_string();
        }
        match name.split_once('.') {
            Some((first, rest)) if first.len() > 8 => {
                let head: String = first.chars().take(4).collect();
                format!("{head}***.{rest}")
            }
            _ => name.to_string(),
        }
    }

    fn dns_name_alerts(&mut self, ts: f64, d: &Decoded<'_>, msg: &DnsMessage) -> Vec<Alert> {
        let name = msg.name.as_str();
        let shown = self.display_name(name);
        let qtype = msg.qtype;
        let detail = format!("name={shown} qtype={qtype}");
        let mut alerts = Vec::new();

        let longest = name.split('.').map(str::len).max().unwrap_or(0);
        let max_name = self.rules.dns_max_name_len;
        let max_label = self.rules.dns_max_label_len;
        let long = name.len() > max_name || longest > max_label;
        if long && self.first_time(name, "dns-long-name") {
            let text = "unusually long DNS name (possible tunneling)";
            let found = alert("dns-long-name", Severity::Medium, ts, d, text);
            alerts.push(found.with_detail(detail.clone()));
        }

        let min_len = self.rules.dns_min_entropy_label_len;
        let threshold = self.rules.dns_entropy_threshold;
        let random = has_random_label(name, min_len, threshold);
        if random && self.first_time(name, "dns-high-entropy") {
            let text = "random-looking DNS label (possible DGA or tunneling)";
            let found = alert("dns-high-entropy", Severity::Medium, ts, d, text);
            alerts.push(found.with_detail(detail.clone()));
        }

        let tld = name.rsplit('.').next().unwrap_or("");
        let bad_tld =
            name.contains('.') && self.rules.suspicious_tlds.iter().any(|t| t.as_str() == tld);
        if bad_tld && self.first_time(name, "dns-suspicious-tld") {
            let text = "DNS name under a suspicious top-level domain";
            let found = alert("dns-suspicious-tld", Severity::Low, ts, d, text);
            alerts.push(found.with_detail(detail));
        }
        alerts
    }
}

/// Reads a whole capture and reports every alert through `on_alert`.
pub fn analyze_reader<R: Read, F: FnMut(Alert)>(
    reader: R,
    rules: &Rules,
    mut on_alert: F,
) -> Result<Stats, PcapError> {
    let mut pcap = PcapReader::new(reader)?;
    let link_type = pcap.link_type();
    let mut analyzer = Analyzer::new(rules.clone());
    while let Some(packet) = pcap.next_packet()? {
        for found in analyzer.packet(link_type, &packet) {
            on_alert(found);
        }
    }
    Ok(analyzer.stats().clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcap::LINKTYPE_ETHERNET;
    use crate::test_util::{dns_message, pcap_file, tcp_frame, udp_frame};

    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    const DNS: [u8; 4] = [10, 0, 0, 53];

    fn run(rules: &Rules, packets: &[(f64, Vec<u8>)]) -> (Vec<Alert>, Stats) {
        let bytes = pcap_file(LINKTYPE_ETHERNET, packets);
        let mut alerts = Vec::new();
        let stats = analyze_reader(bytes.as_slice(), rules, |a| alerts.push(a)).unwrap();
        (alerts, stats)
    }

    fn query(ts: f64, name: &str) -> (f64, Vec<u8>) {
        let message = dns_message(name, 1, false, 0);
        (ts, udp_frame(A, DNS, (40000, 53), &message))
    }

    fn named<'a>(alerts: &'a [Alert], rule: &str) -> Vec<&'a Alert> {
        alerts.iter().filter(|a| a.rule == rule).collect()
    }

    #[test]
    fn flags_suspicious_ports_once_per_flow() {
        let packets = vec![
            (1.0, tcp_frame(A, B, (5000, 4444), TCP_SYN)),
            (2.0, tcp_frame(A, B, (5001, 4444), TCP_SYN)),
            (3.0, tcp_frame(B, A, (4444, 5000), TCP_SYN | TCP_ACK)),
            (4.0, tcp_frame(A, B, (5000, 80), TCP_SYN)),
        ];
        let (alerts, stats) = run(&Rules::default(), &packets);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule, "suspicious-port");
        assert_eq!(alerts[0].src, "10.0.0.1");
        assert_eq!(alerts[0].severity, Severity::Medium);
        assert_eq!(stats.packets, 4);
        assert_eq!(stats.decoded, 4);
        assert_eq!(stats.alerts, 1);
    }

    #[test]
    fn detects_port_scans_inside_one_window_only() {
        let mut fast = Vec::new();
        let mut slow = Vec::new();
        for port in 1..=20u16 {
            let frame = tcp_frame(A, B, (40000, port), TCP_SYN);
            fast.push((f64::from(port) * 0.1, frame.clone()));
            slow.push((f64::from(port) * 11.0, frame));
        }
        let (alerts, _) = run(&Rules::default(), &fast);
        let scans = named(&alerts, "port-scan");
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].severity, Severity::High);
        let (alerts, _) = run(&Rules::default(), &slow);
        assert!(named(&alerts, "port-scan").is_empty());
    }

    #[test]
    fn flags_long_dns_names_and_masks_them() {
        let label = "a".repeat(45);
        let name = format!("{label}.example.com");
        let (alerts, stats) = run(&Rules::default(), &[query(1.0, &name)]);
        let found = named(&alerts, "dns-long-name");
        assert_eq!(found.len(), 1);
        let detail = found[0].detail.as_deref().unwrap();
        assert!(detail.contains("aaaa***.example.com"));
        assert!(!detail.contains(&label));
        assert_eq!(stats.dns_queries, 1);
    }

    #[test]
    fn masking_can_be_disabled() {
        let label = "a".repeat(45);
        let name = format!("{label}.example.com");
        let rules = Rules {
            mask_names: false,
            ..Rules::default()
        };
        let (alerts, _) = run(&rules, &[query(1.0, &name)]);
        let detail = alerts[0].detail.as_deref().unwrap();
        assert!(detail.contains(&label));
    }

    #[test]
    fn flags_random_looking_labels_but_not_plain_names() {
        let packets = vec![
            query(1.0, "x8k2jf9sl2kd93jf7q.example.com"),
            query(2.0, "www.example.com"),
            query(3.0, "mail.google.com"),
        ];
        let (alerts, _) = run(&Rules::default(), &packets);
        let found = named(&alerts, "dns-high-entropy");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].timestamp, 1.0);
    }

    #[test]
    fn flags_suspicious_tlds_once_per_name() {
        let packets = vec![
            query(1.0, "evil.tk"),
            query(2.0, "evil.tk"),
            query(3.0, "ok.org"),
        ];
        let (alerts, _) = run(&Rules::default(), &packets);
        let found = named(&alerts, "dns-suspicious-tld");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].severity, Severity::Low);
    }

    #[test]
    fn detects_query_bursts_once_per_window() {
        let rules = Rules {
            dns_burst_threshold: 5,
            ..Rules::default()
        };
        let mut packets = Vec::new();
        for i in 0..8u32 {
            let ts = f64::from(i) * 0.1;
            packets.push(query(ts, &format!("q{i}.example.com")));
        }
        let (alerts, stats) = run(&rules, &packets);
        assert_eq!(named(&alerts, "dns-query-burst").len(), 1);
        assert_eq!(stats.dns_queries, 8);
    }

    #[test]
    fn detects_nxdomain_bursts() {
        let rules = Rules {
            nxdomain_threshold: 3,
            ..Rules::default()
        };
        let mut packets = Vec::new();
        for i in 0..4u32 {
            let message = dns_message(&format!("n{i}.example.com"), 1, true, 3);
            let frame = udp_frame(DNS, A, (53, 40000), &message);
            packets.push((f64::from(i), frame));
        }
        let (alerts, _) = run(&rules, &packets);
        let found = named(&alerts, "dns-nxdomain-burst");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].severity, Severity::High);
        assert_eq!(found[0].dst, "10.0.0.1");
    }

    #[test]
    fn ignores_malformed_dns_and_unrelated_traffic() {
        let junk = udp_frame(A, DNS, (40000, 53), &[1, 2, 3]);
        let web = tcp_frame(A, B, (5000, 443), TCP_SYN);
        let (alerts, stats) = run(&Rules::default(), &[(1.0, junk), (2.0, web)]);
        assert!(alerts.is_empty());
        assert_eq!(stats.packets, 2);
        assert_eq!(stats.dns_queries, 0);
    }

    #[test]
    fn undecodable_packets_are_counted_but_skipped() {
        let (alerts, stats) = run(&Rules::default(), &[(1.0, vec![0u8; 3])]);
        assert!(alerts.is_empty());
        assert_eq!(stats.packets, 1);
        assert_eq!(stats.decoded, 0);
    }
}
