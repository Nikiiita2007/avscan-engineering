//! Detection thresholds. Every field can be overridden from the module config.

use serde::Deserialize;

/// Tunable detection rules; unknown keys are rejected.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Rules {
    /// Destination ports that are suspicious by themselves.
    pub suspicious_ports: Vec<u16>,
    /// Top-level domains that are flagged (lowercase, without dot).
    pub suspicious_tlds: Vec<String>,
    pub dns_max_name_len: usize,
    pub dns_max_label_len: usize,
    /// Shannon entropy (bits per character) above which a label looks random.
    pub dns_entropy_threshold: f64,
    /// Labels shorter than this are never checked for entropy.
    pub dns_min_entropy_label_len: usize,
    /// DNS queries from one host per window that count as a burst.
    pub dns_burst_threshold: u32,
    /// NXDOMAIN answers to one host per window that count as a burst.
    pub nxdomain_threshold: u32,
    /// Distinct TCP ports probed on one host per window that count as a scan.
    pub port_scan_threshold: u32,
    /// Length of the counting window in seconds.
    pub window_secs: f64,
    /// Hide the payload-bearing part of DNS names in alerts.
    pub mask_names: bool,
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

impl Default for Rules {
    fn default() -> Self {
        Self {
            suspicious_ports: vec![4444, 5555, 6666, 6667, 1337, 31337, 12345, 9001],
            suspicious_tlds: strings(&["tk", "ml", "ga", "cf", "gq", "top"]),
            dns_max_name_len: 100,
            dns_max_label_len: 40,
            dns_entropy_threshold: 3.5,
            dns_min_entropy_label_len: 16,
            dns_burst_threshold: 100,
            nxdomain_threshold: 20,
            port_scan_threshold: 15,
            window_secs: 10.0,
            mask_names: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn partial_override_keeps_other_defaults() {
        let rules: Rules = serde_json::from_value(json!({ "suspicious_ports": [1] })).unwrap();
        assert_eq!(rules.suspicious_ports, [1]);
        assert_eq!(rules.window_secs, Rules::default().window_secs);
        assert!(rules.mask_names);
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let result = serde_json::from_value::<Rules>(json!({ "bogus": 1 }));
        assert!(result.is_err());
    }

    #[test]
    fn defaults_are_sane() {
        let rules = Rules::default();
        assert!(rules.suspicious_ports.contains(&4444));
        assert!(rules.dns_max_label_len <= 63);
        assert!(rules.window_secs > 0.0);
    }
}
